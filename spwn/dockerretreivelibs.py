#!/usr/bin/env python3

import os
import io
import tarfile

import docker.errors

from spwn.binary import Binary
from spwn.libc import Libc
from spwn.configmanager import ConfigManager

import docker
from docker.client import DockerClient
from docker.models.images import Image

import tempfile

from elftools.elf.elffile import ELFFile
from elftools.elf.dynamic import DynamicSection
from elftools.elf.gnuversions import GNUVerNeedSection, GNUVerDefSection

class DockerAnalyzer:
    def __init__(self, configs:ConfigManager):
        self.tars:dict[io.BytesIO] = {}
        self.binary:str = None
        self.image:Image = None
        self.client:DockerClient = None
        self.libc:str = None
        self.configs = configs

    def find_binary(self) -> str:
        entrys = ''.join(self.image.attrs['ContainerConfig']['Cmd'] + self.image.attrs['ContainerConfig']['Entrypoint'])

        for file in os.listdir():
            if file in entrys:
                return file

        raise FileNotFoundError('No binary found in either CMD or Entrypoint')

    def get_shared_libraries_and_paths(self, binary:str) -> tuple[list[str]]:
        with open(binary, 'rb') as file:
            elffile = ELFFile(file)

            dynamic_section = None
            for section in elffile.iter_sections():
                if isinstance(section, DynamicSection):
                    dynamic_section = section
                    break

            if not dynamic_section:
                raise Exception("No dynamic section found in the binary.")

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

    def get_libc_version(self, file:io.BytesIO):
        elffile = ELFFile(file)

        version_names = set()
        for section in elffile.iter_sections():
            if isinstance(section, (GNUVerNeedSection, GNUVerDefSection)):
                for version in section.iter_versions():
                    for aux in version.iter_aux():
                        version_names.add(aux.name)

        return version_names
    
    def get_dependencies(self,) -> tuple[list[str]]:
        self.client = docker.from_env()

        tag = os.path.basename(os.getcwd())

        print(f'[*] building container with tag: {tag}')

        self.image, build_logs = self.client.images.build(path='.', quiet=False, tag=tag)

        for log in build_logs:
            print(log.get('stream', ''), end='')

        self.binary = self.find_binary()

        print(f'[*] found binary: {self.binary}')

        self.libraries, self.search_dirs = self.get_shared_libraries_and_paths(self.binary)

        for lib in list(filter(lambda lib: 'libc' in lib, self.libraries)):
            self.libc = lib
            self.libraries.remove(lib)

        self.additional_libs = self.libraries

        return self.binary, self.libc, list(self.libraries)

    def extract(self, member_name:str, is_tmp_file:bool=False) -> tuple[Binary, Libc,]:
        for path in self.search_dirs:
            if not path in self.tars:
                tar_object = self.get_tar_from_path(path)
                if tar_object is None:      # Path to extract not found
                    continue
                self.tars.update({path:tar_object})

            with tarfile.open(fileobj=tar_object) as tar:
                hits = [member for member in tar.getmembers()]
                if hits: 
                    break
        member = hits[0]
        member_name = os.path.basename(member.name)
        while member.issym():
            member = tar.getmember(member.linkname)

        #print(f'[*] extracting {member_name}')
        if not is_tmp_file:
            print(f'[*] extracting {member_name} to {self.configs.docker_extract_path}')

        file_name = tempfile.mkstemp()[1] if is_tmp_file else os.path.join(self.configs.docker_extract_path, member_name)

        tar._extract_member(member, file_name)

        return file_name