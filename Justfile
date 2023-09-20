image_name := "trivy-web"
image_tag := "2023-09-10-2"

build:
  docker build -t "{{ image_name }}:{{ image_tag }}" .

run:
  docker run -it --rm -p 16223:16223 "{{ image_name }}:{{ image_tag }}" --binding=0.0.0.0:16223

push:
  docker push "{{ image_name }}:{{ image_tag }}" athallerde/{{ image_name }}:{{ image_tag }}

deploy:
  oc apply -f kubernetes/deployment.yaml
  oc apply -f kubernetes/service.yaml
  oc apply -f kubernetes/route.yaml