FROM public.ecr.aws/amazonlinux/amazonlinux:2023

RUN mkdir /app && \
     curl -LO https://bootstrap.pypa.io/get-pip.py && \
     python3 get-pip.py && \
     python3 -m pip install psec boto3 pycryptodome

COPY tr34/import_app/ /app
WORKDIR /app

ENTRYPOINT ["python3", "apc_demo_keysetup.py"]