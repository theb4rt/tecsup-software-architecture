FROM ubuntu:22.04

RUN apt update && apt install -y \
    mysql-server \
    nginx \
    python3 \
    openjdk-17-jdk \
    && apt clean

CMD ["/bin/bash"]
