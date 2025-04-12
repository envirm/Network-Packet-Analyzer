# Build the image
docker build -t my-kali .

# Run the container
docker run -it --rm --name kali my-kali
