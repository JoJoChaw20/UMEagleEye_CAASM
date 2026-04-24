FROM python:3.12-slim

WORKDIR /app

# Install system dependencies for scanning tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    nmap \
    gcc \
    libpq-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install masscan from source
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    make \
    libc6-dev \
    libpcap-dev \
    && git clone https://github.com/robertdavidgraham/masscan /tmp/masscan \
    && cd /tmp/masscan \
    && make -j$(nproc) \
    && cp bin/masscan /usr/local/bin/ \
    && rm -rf /tmp/masscan \
    && apt-get purge -y git make \
    && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/*

# Install Syft and Grype
RUN curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sh -s -- -b /usr/local/bin \
    && curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
