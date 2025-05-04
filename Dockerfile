# Use Python 3.11 as the base image
FROM python:3.11

RUN apt-get update && apt-get install -y ca-certificates && update-ca-certificates

# Set the working directory
WORKDIR /app

# Copy project files to the container
COPY . .
COPY cacert.pem /app/cacert.pem
# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

RUN pip install --upgrade certifi

EXPOSE 9000
EXPOSE 9001

# Run the Flask app
# CMD ["gunicorn", "-w", "4", "-b", "0.0.0.0:9000", "app:app"]
CMD ["python3", "-u", "app.py"]