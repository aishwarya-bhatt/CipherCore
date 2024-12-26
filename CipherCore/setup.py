from setuptools import setup

setup(
    name='CipherCore',
    version='1.0',
    packages=['src'],
    install_requires=[
        # List dependencies here if any
    ],
    entry_points={
        'console_scripts': [
            'file-encryptor = src.file_encryptor:main',  # Adjust if you create a main function
        ],
    },
)
