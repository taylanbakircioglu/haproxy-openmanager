FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    postgresql-client \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user for OpenShift compatibility
RUN groupadd --gid 1001 appgroup && \
    useradd --uid 1001 --gid appgroup --shell /bin/bash --create-home appuser

# Copy requirements and install Python dependencies
COPY requirements.txt requirements-test.txt ./
RUN pip install --no-cache-dir -r requirements.txt && \
    pip install --no-cache-dir -r requirements-test.txt

# Copy application code
COPY . .

# Run unit tests during build (fails build if tests fail)
RUN python -m pytest tests/ -v --tb=short --disable-warnings || \
    (echo "❌ UNIT TESTS FAILED - Build aborted" && exit 1)

# Remove test dependencies to reduce image size
RUN pip uninstall -y pytest pytest-asyncio pytest-mock pytest-cov httpx

# Create haproxy config directory and set permissions
RUN mkdir -p /etc/haproxy && \
    chown -R appuser:appgroup /app /etc/haproxy

# Switch to non-root user
USER appuser

# Expose port
EXPOSE 8000

# Run the application in production mode (without --reload)
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]