from setuptools import setup, find_packages

def read_requirements():
    with open('requirements.txt') as req:
        return [line.strip() for line in req if line.strip() and not line.startswith('#')]

setup(
    name='otx2misp', 
    version='1.1',
    author='guangamber',
    author_email='guangamber',
    description='A short description of your project', 
    long_description=open('README.md').read(), 
    long_description_content_type='text/markdown',
    url='https://github.com/guangamber/otx2misp', 
    package_dir={'': 'src'},
    packages=find_packages(where='src'),
    install_requires=read_requirements(),
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: Apache License', 
        'Programming Language :: Python :: 3', 
        'Programming Language :: Python :: 3.6',
        'Programming Language :: Python :: 3.7',
        'Programming Language :: Python :: 3.8',
    ],
    entry_points={
        'console_scripts': [
            'otx2misp=otx2misp.main:main'
        ]
    },
)
