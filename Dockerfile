# Use Python 3.11 as the base image
FROM python:3.11

# Set the working directory
WORKDIR /app

# Copy project files to the container
COPY . .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

EXPOSE 9000

# Run the Flask app
CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:9000", "app:app"]
