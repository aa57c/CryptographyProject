
# Use an official Python runtime as a parent image
FROM python:3.10-slim

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV OQS_VERSION="main"

# Install required packages for building liboqs
RUN apt-get update && \
    apt-get install -y cmake make gcc g++ git libssl-dev && \
    rm -rf /var/lib/apt/lists/*

# Clone and install liboqs
RUN git clone --branch ${OQS_VERSION} https://github.com/open-quantum-safe/liboqs.git /liboqs && \
    cd /liboqs && \
    cmake -DBUILD_SHARED_LIBS=ON -S . -B build && \
    cmake --build build && \
    cmake --install build && \
    cd / && \
    rm -rf /liboqs

# Set library path
ENV LD_LIBRARY_PATH=/usr/local/lib:$LD_LIBRARY_PATH

# Refresh shared library cache
RUN ldconfig

# Set the working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the working directory contents into the container at /app
COPY . .

# Make port 5600 available to the world outside this container
EXPOSE 5600

# Run app.py when the container launches
CMD ["python", "app.py"]
