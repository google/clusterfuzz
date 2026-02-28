FROM mcr.microsoft.com/devcontainers/base:noble

# Prevent interactive prompts during package installation.
ENV DEBIAN_FRONTEND=noninteractive

# Install Python 3.11 and other essential tools.
# Ubuntu 24.04 (Noble) doesn't have Python 3.11 in its main repos by default.
# We'll use the deadsnakes PPA to install it.
RUN apt-get update && apt-get install -y --no-install-recommends \
    software-properties-common \
    && add-apt-repository ppa:deadsnakes/ppa \
    && apt-get update && apt-get install -y --no-install-recommends \
    python3.11 \
    python3.11-dev \
    python3.11-venv \
    python3.11-distutils \
    build-essential \
    libssl-dev \
    libffi-dev \
    && apt-get clean && rm -rf /var/lib/apt/lists/*

# Install pip for Python 3.11 and pipenv.
RUN curl -sS https://bootstrap.pypa.io/get-pip.py | python3.11 \
    && python3.11 -m pip install --no-cache-dir pipenv

# Set Python 3.11 as the default python3.
# Using ln -sf to avoid update-alternatives issues in the build process.
RUN ln -sf /usr/bin/python3.11 /usr/bin/python3 \
    && ln -sf /usr/bin/python3.11 /usr/bin/python

# Set the working directory.
WORKDIR /workspace

# Set the default shell to bash.
ENV SHELL=/bin/bash
