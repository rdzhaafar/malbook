import zipfile as zip
import os

from .framework import Task
from .errors import Error


class UnzipSample(Task):
    needs = [
        'zipped_sample_path',
        'zipped_sample_output'
    ]

    provides = [
        'unzipped_sample_path'
    ]

    def run(self):
        sample_path = self.get('zipped_sample_path')
        password = self.get('zipped_sample_password')
        if type(password) != bytes:
            raise Error("Zipped sample password must be a byte string")

        output_dir = self.get('zipped_sample_output')
        os.makedirs(output_dir, exist_ok=True)
        with zip.ZipFile(sample_path, 'r') as compressed_sample:
            compressed_sample.extractall(output_dir, pwd=password)

        self.set('unzipped_sample_path', output_dir)
