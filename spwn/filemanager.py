#!/usr/bin/env python3

import os
import io
import tarfile
import re
import shutil
import subprocess
import tempfile
import platform

from pwnlib.elf import ELF

import spwn.utils as utils
from spwn.binary import Binary
from spwn.libc import Libc
from spwn.lib import Lib
from spwn.loader import Loader
from spwn.configmanager import ConfigManager

import docker
import docker.errors
from docker.client import DockerClient
from docker.models.images import Image

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection

class FileManager:
    def __init__(self, configs:ConfigManager):
        self.tars:dict[str, tuple[io.BytesIO, list[str]]] = {}
        self.binary_name:str = None
        self.binary:Binary = None
        self.image:Image = None
        self.client:DockerClient = None
        self.libc:Libc = None
        self.loader:Loader = None
        self.other_libs:dict[str, Lib] = {}
        self.configs = configs
        self.version:str = None
        self.arch:str = None
        self.version_string:str = None

    def find_binary(self) -> str:

        if self.image is None:
            candidates = [candidate for candidate in os.listdir() if platform.architecture(candidate)[1] == "ELF" and not (candidate.startswith('lib') or candidate.startswith('ld-'))]
            return utils.ask_list('Please chose the binary: ', candidates, False)

        entrys = ''.join((self.image.attrs['Config']['Cmd'] or []) + (self.image.attrs['Config']['Entrypoint'] or []))

        for file in os.listdir():
            if file in entrys:
                return file

        raise FileNotFoundError('No binary found in either CMD or Entrypoint')

    def get_shared_libraries_and_paths(self, binary:str) -> tuple[list[str]]:
        with open(binary, 'rb') as file:
            elffile = ELFFile(file)

            dynamic_section = None
            interpreter = None

            for section in elffile.iter_sections():
                if isinstance(section, DynamicSection):
                    dynamic_section = section
                    break

            if not dynamic_section:
                raise Exception("No dynamic section found in the binary.")

            for segment in elffile.iter_segments():
                if segment.header.p_type == 'PT_INTERP':
                    interpreter = segment.get_interp_name()
                    break

            needed_libraries = []
            rpath = []
            runpath = []
            ldlibpath = []

            for tag in dynamic_section.iter_tags():
                if tag.entry.d_tag == 'DT_NEEDED':
                    needed_libraries.append(tag.needed)
                elif tag.entry.d_tag == 'DT_RPATH':
                    rpath = tag.rpath.split(':')
                elif tag.entry.d_tag == 'DT_RUNPATH':
                    runpath = tag.runpath.split(':')

            if 'LD_LIBRARY_PATH' in os.environ:
                ldlibpath = os.environ.get('LD_LIBRARY_PATH', '').split(':')

            # Combine rpath and runpath for search directories
            search_dirs = rpath + runpath + ldlibpath + ['/lib/', '/usr/lib/', '/lib64/', '/usr/lib64/']

            if interpreter:
                needed_libraries.append(interpreter)

            return set(needed_libraries), search_dirs
    def get_tar_from_path(self, path:str) -> io.BytesIO:
        container = self.client.containers.create(self.image.id)

        try:        # Path to extract not found
            stream, _ = container.get_archive(path)
        except docker.errors.NotFound:
            container.remove()
            return None

        tar_object = io.BytesIO()
        for chunk in stream:
            tar_object.write(chunk)
        tar_object.seek(0)

        container.remove()

        return tar_object
    
    def get_ubuntu_version_string(self, file:str) -> str | None:
        with open(file, "rb") as f:
            content = f.read()
        match = re.search(r"\d+\.\d+-\d+ubuntu\d+(\.\d+)?".encode(), content)

        if match:
            return match.group().decode()
        else:
            return None
    
    def get_libc_version(self, file_path:str):
        return platform.libc_ver(file_path)[1], ELF(file_path, checksec=False).get_machine_arch(), self.get_ubuntu_version_string(file_path)

    def get_libc_version_buffer(self, tar_obj:io.BytesIO, file_name:str) -> str:
        temp_file = tempfile.mkstemp()[1]

        tar_obj.seek(0)

        with tarfile.open(fileobj=tar_obj) as tar:
            tar._extract_member(tar.getmember(file_name), temp_file)

        version, arch, version_string = self.get_libc_version(temp_file)

        os.remove(temp_file)

        print(f'[+] ubuntu version: {version}, arch: {arch}')

        return version, arch, version_string

    def build_container(self):
        self.client = docker.from_env()

        tag = os.path.basename(os.getcwd())

        print(f'[*] building container with tag: {tag}')

        self.image, build_logs = self.client.images.build(path='.', quiet=False, tag=tag)

        for log in build_logs:
            print(log.get('stream', ''), end='')

    def populate_tars(self):
        for path in self.search_dirs:
            if not path in self.tars:
                tar_object = self.get_tar_from_path(path)
                if tar_object is None:      # Path to extract not found
                    continue
                with tarfile.open(fileobj=tar_object) as tar:
                    self.tars.update({path:(tar_object, tar.getnames())})

                tar_object.seek(0)

    def extract_file(self, tar_object:io.BytesIO, tar_name:str, out_path:str):
       
        tar_object.seek(0)
        with tarfile.open(fileobj=tar_object) as tar:
            content = tar.extractfile(tar_name)

            with open(out_path, 'wb') as f:
                f.write(content.read())
    
    def auto_recognize(self,) -> tuple[list[str]]:
        if 'Dockerfile' in os.listdir():
            self.build_container()
        else:
            print('[-] No Dockerfile found in local directory.')

        self.binary_name = self.find_binary()

        print(f'[*] found binary: {self.binary_name}')

        libs, self.search_dirs = self.get_shared_libraries_and_paths(self.binary_name)

        if self.image is not None:
            self.populate_tars()

        self.libraries = {}

        local_files = set(os.listdir())

        def compare_file_names(name1:str, name2:str) -> bool:
            m1, m2 = re.match(r'^(\S+?)[.-]', name1), re.match(r'^(\S+?)[.-]', name2)
            res = m1 and m2 and m1.groups() == m2.groups()
            return res

        def search_local(libname):
            for file in local_files:
                if compare_file_names(os.path.basename(file), libname):
                    if 'libc.' in file or 'libc-' in file:
                        self.version, self.arch, self.version_string = self.get_libc_version(file)
                    return {libname:(f'{libname} (local)', file)}
            return None

        def search_docker(libname):
            for path, (tar_object, files) in self.tars.items():
                for file in files:
                    if compare_file_names(os.path.basename(file), libname):
                        if 'libc.' in file or 'libc-' in file:
                            self.version, self.arch, self.version_string = self.get_libc_version_buffer(tar_object, file)
                            out_path = os.path.normpath(os.path.join(self.configs.extract_dir, f'libc-{self.version}.so'))
                            self.extract_file(tar_object, file, out_path)
                        else:
                            out_path = os.path.normpath(os.path.join(self.configs.extract_dir, os.path.basename(file)))
                            self.extract_file(tar_object, file, out_path)
                        return {libname:(f'{libname} (docker)', out_path)}
            return None

        for lib in libs:
            libname = os.path.basename(lib)
            result = search_local(libname) or search_docker(libname)
            if not result is None:
                self.libraries.update(result)

        missing_libs = [lib for lib in libs if not os.path.basename(lib) in self.libraries]

        if self.version is not None and any(missing_libs):    # test if there are any unresolved dependencies
            temp_dir = self.get_online(self.version_string, self.arch)
            for lib in missing_libs:
                lib_name = os.path.basename(lib)
                for sdir in self.search_dirs:
                    lib_path = os.path.normpath(os.path.join(temp_dir, sdir, lib_name))
                    if os.path.exists(lib_path) and os.path.isfile(lib_path):
                        file = os.path.normpath(os.path.join(self.configs.extract_dir, lib_name))
                        shutil.copyfile(lib_path, file)
                        self.libraries.update({lib_name:(f'{lib_name} (online)', file)})
                        break
                else:
                    self.libraries.update({lib:(f'{lib_name} (not found)', None)})


        print('[+] Dependencies:')
        # print('\n'.join([f' - {desc}' for file, (desc, path) in self.libraries.items()]))

        self.binary = Binary(self.binary_name)

        for file, (desc, path) in self.libraries.items():
            print(f' - {desc}')
            if 'libc.' in file or 'libc-' in file:
                self.libc = Libc(path)
            elif str(file).startswith('ld'):
                self.loader = Loader(path)
            else:
                self.other_libs.update({file:Lib(path)})
            

    def extract(self, member_name:str, is_tmp_file:bool=False) -> tuple[Binary, Libc,]:
        for path in self.search_dirs:
            if not path in self.tars:
                tar_object = self.get_tar_from_path(path)
                if tar_object is None:      # Path to extract not found
                    continue
                self.tars.update({path:tar_object})

            with tarfile.open(fileobj=tar_object) as tar:
                hits = [*filter(lambda member: member_name in member.name, tar.getmembers())]
                if hits: 
                    break
        member = hits[0]
        member_name = os.path.basename(member.name)
        while member.issym():
            member = tar.getmember(member.linkname)

        if not is_tmp_file:
            print(f'[*] extracting {member_name} to {self.configs.docker_extract_path}')

        file_name = tempfile.mkstemp()[1] if is_tmp_file else os.path.join(self.configs.docker_extract_path, member_name)

        tar._extract_member(member, file_name)

        return file_name
    
    def get_online(self, version:str, arch:str) -> None:
        package_name = f"libc6_{version}_{arch}.deb"
        package_url  = f"https://launchpad.net/ubuntu/+archive/primary/+files/{package_name}"
        tempdir = tempfile.mkdtemp()

        print(f"[+] Downloading loader from {package_url}")
        if not utils.download_package(package_url, tempdir):
            shutil.rmtree(tempdir)
            print('[-] Download failed')
            return

        print("[+] Extracting loader")
        if not utils.extract_deb(tempdir):
            print('[-] Extracting failed')
            shutil.rmtree(tempdir)
            return

        if not utils.find_and_extract_data(tempdir):
            print('[-] Extracting data failed')
            shutil.rmtree(tempdir)
            return
        
        return tempdir
    
    def patchelf(self) -> None:
        if self.loader:
            try:
                subprocess.check_call(["patchelf", "--set-interpreter", f"./{self.loader.debug_name}", "--set-rpath", f"./{self.configs.debug_dir}", self.binary.debug_name])
            except subprocess.CalledProcessError:
                print("[!] patchelf failed")
        else:
            try:
                subprocess.check_call(["patchelf", "--set-rpath", f"./{self.configs.debug_dir}", self.binary_name.debug_name])
            except subprocess.CalledProcessError:
                print("[!] patchelf failed")