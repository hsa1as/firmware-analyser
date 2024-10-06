FROM ubuntu:20.04
RUN apt-get -y update && apt-get install -y locales && rm -rf /car/lib/apt/lists* \
    && localedef -i en_US -c -f UTF-8 -A /usr/share/locale/locale.alias en_US.UTF-8
ENV LANG en_US.utf8
RUN apt -y install default-jre openjdk-21-jdk openjdk-21-jre
RUN apt -y install python3 python3-pip wget snapd unzip
WORKDIR /opt/
# Pyhjdra doesn't seem to work with ghidra 11.2
#RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20240926.zip
#RUN unzip ghidra_11.2_PUBLIC_20240926.zip && mv ghidra_11.2_PUBLIC ghidra
RUN wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.0.2_build/ghidra_11.0.2_PUBLIC_20240326.zip
RUN unzip ghidra_11.0.2_PUBLIC_20240326.zip && mv ghidra_11.0.2_PUBLIC ghidra
ENV GHIDRA_INSTALL_DIR /opt/ghidra/
RUN apt -y install automake ssdeep libtool
ENV BUILD_LIB 1
RUN pip3 install pyhidra python-tlsh ssdeep
WORKDIR /usr/src/app
COPY DumpFunctionInformation_FA.py ./app.py

