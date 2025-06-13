from setuptools import setup, find_packages

setup(
    name='NotYourIP',
    version='0.1.0',
    description='User agent and IP filtering package',
    long_description=open('README.md', encoding='utf-8').read(),
    long_description_content_type='text/markdown',
    author='lunarist._.dev',
    author_email='isvalidatednull@gmail.com',
    url='https://github.com/lunarist-dev/NotYourIP',
    python_requires='>=3.6',
    packages=find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "Operating System :: OS Independent",
        "License :: OSI Approved :: MIT License",
    ],
    install_requires=[
        "requests",
    ],
)
