import zipfile as zip
import uuid
import os
from os import path

from .framework import Task, Notebook, Error


class UnzipSample(Task):
    '''
    `UnzipSample` unzips a malware sample located in 
    `zipped_sample_path` and provides `sample_path`.
    If `zipped_sample_password` is defined, `UnzipSample` uses
    it as archive password. 
    '''

    def run(self, notebook: Notebook) -> None:
        sample_path = self.get_required_variable('zipped_sample_path', notebook)
        password = notebook.get('zipped_sample_password')

        # XXX: Create unique directory for outputting the sample
        output_dir = path.join(os.getcwd(), str(uuid.uuid4()))
        os.mkdir(output_dir)

        # XXX: Unzip the sample
        with zip.ZipFile(sample_path, 'r') as compressed_sample:
            if password is not None:
                compressed_sample.extractall(output_dir, pwd=password)
            else:
                compressed_sample.extractall(output_dir)

        # XXX: We assume that the malware sample is the only file inside the archive
        files = os.listdir(output_dir)
        if len(files) != 1:
            raise Error('Malware sample is not the only file zip archive')

        sample_path = path.join(output_dir, files[0])
        notebook.set('sample_path', sample_path)
