image_name := "trivy-web"
image_tag := "2024-07-24-1"

build:
    docker build -t "{{ image_name }}:{{ image_tag }}" .

run:
    docker run -it --rm -p 16223:16223 "{{ image_name }}:{{ image_tag }}" --binding=0.0.0.0:16223

push:
    docker tag "{{ image_name }}:{{ image_tag }}" "athallerde/{{ image_name }}:{{ image_tag }}"
    docker push "athallerde/{{ image_name }}:{{ image_tag }}"

deploy:
    find kubernetes -type f -exec oc apply -f {} \;

undeploy:
    find kubernetes -type f -exec oc delete -f {} \;

deploy-local:
  git pull
  cargo install --path .
  mv ~/.cargo/bin/trivy-web /opt/pot/jails/trivy/m/usr/local/bin/trivy-web
  pot exec -p trivy supervisorctl restart trivy-web-0
  sleep 1
  pot exec -p trivy supervisorctl restart trivy-web-1
