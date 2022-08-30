import setuptools


with open("README.md") as fp:
    long_description = fp.read()


setuptools.setup(
    name="ec2_imagebuilder_ami_lifecycle",
    version="0.0.1",

    description="CDK stack with an EC2 Image Builder component and associated AMI Lifecycle.",
    long_description=long_description,
    long_description_content_type="text/markdown",

    author="Damian Francis McDonald",
    author_email="damiamcd at amazon.es",

    package_dir={"": "ec2_imagebuilder_ami_lifecycle"},
    packages=setuptools.find_packages(where="ec2_imagebuilder_ami_lifecycle"),

    install_requires=[
        "aws-cdk.core==1.168.0",
    ],

    python_requires=">=3.6",

    classifiers=[
        "Development Status :: 4 - Beta",

        "Intended Audience :: Developers",

        "Programming Language :: JavaScript",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",

        "Topic :: Software Development :: Code Generators",
        "Topic :: Utilities",

        "Typing :: Typed",
    ],
)
