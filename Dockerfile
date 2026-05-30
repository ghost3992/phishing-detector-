# Use official Python slim image
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first (for better layer caching)
COPY requirements.txt .

# Upgrade pip using python -m pip (always works, no PATH issues)
RUN python -m pip install --upgrade pip

# Install dependencies
RUN python -m pip install -r requirements.txt

# Copy the rest of the app
COPY . .

# Expose port
EXPOSE 8000

# Start with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8000", "app:app"]
