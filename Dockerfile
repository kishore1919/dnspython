# Stage 1: Build stage
# Use a specific Python version. pyproject.toml requires >=3.13, but 3.13 is not stable yet.
# Using Python 3.12.
FROM python:3.12-slim as builder

# Set the working directory
WORKDIR /app

# Install build dependencies if any (e.g., for packages that need compilation)
# RUN apt-get update && apt-get install -y --no-install-recommends gcc

# Copy dependency files
COPY pyproject.toml requirements.txt ./

# Install uv, a fast Python package installer
RUN pip install uv

# Install dependencies using uv
RUN uv pip install --system --no-cache -r requirements.txt

# Stage 2: Final stage
FROM python:3.12-slim

WORKDIR /app

# Copy installed dependencies from the builder stage
COPY --from=builder /usr/local/lib/python3.12/site-packages /usr/local/lib/python3.12/site-packages

# Copy the application code
COPY . .

# Command to run the application, as mentioned in README.md
CMD ["python", "main.py"]