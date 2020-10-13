import setuptools

with open('README.md', 'r') as fh:
  long_description = fh.read()

setuptools.setup(
    name='clusterfuzz',
    version='0.0.1',
    author='ClusterFuzz authors',
    author_email='clusterfuzz-announce@googlegroups.com',
    description='ClusterFuzz',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/google/clusterfuzz',
    packages=setuptools.find_packages(),
    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
    ],
    python_requires='>=3.7',
)

# TODO(ochang): Add and minimize dependencies.
