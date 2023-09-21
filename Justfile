image_name := "trivy-web"
image_tag := "2023-09-21-1"

build:
  docker build -t "{{ image_name }}:{{ image_tag }}" .

run:
  docker run -it --rm -p 16223:16223 "{{ image_name }}:{{ image_tag }}" --binding=0.0.0.0:16223

push:
  docker push "{{ image_name }}:{{ image_tag }}" athallerde/{{ image_name }}:{{ image_tag }}

deploy:
  oc apply -f kubernetes/client/deployment.yaml
  oc apply -f kubernetes/client/route.yaml
  oc apply -f kubernetes/client/service.yaml
  oc apply -f kubernetes/server/deployment.yaml
  oc apply -f kubernetes/server/service.yaml
  oc apply -f kubernetes/redis/statefulset.yaml
  oc apply -f kubernetes/redis/service.yaml

undeploy:
  oc delete -f kubernetes/client/deployment.yaml
  oc delete -f kubernetes/client/route.yaml
  oc delete -f kubernetes/client/service.yaml
  oc delete -f kubernetes/server/deployment.yaml
  oc delete -f kubernetes/server/service.yaml
  oc delete -f kubernetes/redis/statefulset.yaml
  oc delete -f kubernetes/redis/service.yaml