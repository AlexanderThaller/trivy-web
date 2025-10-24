image_name := "trivy-web"
image_tag := "2024-07-24-1"

@_default:
    @just --list

# Build the Docker image
build:
    docker build -t "{{ image_name }}:{{ image_tag }}" .

# Run the Docker container
run:
    docker run -it --rm -p 16223:16223 "{{ image_name }}:{{ image_tag }}" --binding=0.0.0.0:16223

# Push the Docker image to Docker Hub
push:
    docker tag "{{ image_name }}:{{ image_tag }}" "athallerde/{{ image_name }}:{{ image_tag }}"
    docker push "athallerde/{{ image_name }}:{{ image_tag }}"

# Continuous Integration and Continuous Deployment tasks
cicd:
    act
