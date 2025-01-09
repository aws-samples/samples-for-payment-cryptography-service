#!/usr/bin/env bash
set -e

usage() {
  echo "AWS Lambda Layer Builder"
  echo "------------------------"
  echo "make-layer NAME RUNTIME PACKAGE_1 [PACKAGE_2] ..."
  echo "make-layer NAME RUNTIME MANIFEST"
  echo ""
  echo "Currently supported runtimes: nodejs*, python*"
}

# Check if Docker is installed
if ! command -v docker >/dev/null 2>&1; then
    echo "Docker not found. Installing Docker..."
    sudo yum update -y
    sudo yum install -y docker
    sudo service docker start
    sudo usermod -a -G docker $USER
    newgrp docker
fi

if [[ "$#" -lt 3 ]]; then
   usage
   exit 1
fi

name="${1}"
runtime="${2}"
manifest="${3}"

if test -f "$manifest"; then
  packages="${@:4}"
else
  manifest=""
  packages="${@:3}"
fi

output_folder="$(pwd)/output"
mkdir -p "$output_folder"
echo "Output folder: $output_folder"
docker_image="public.ecr.aws/sam/build-$runtime:latest"
volume_params="-v $output_folder:/layer"

if [[ $runtime == node* ]]; then
  package_folder="nodejs/"
  mkdir -p "$output_folder/$package_folder"
  if [[ -n "$manifest" ]]; then
    cp "$manifest" "$output_folder/$package_folder/package.json"
  fi
  install_command="pushd $package_folder; npm install; npm install --save $packages; popd"
  volume_params="$volume_params -v $HOME/.npmrc:/root/.npmrc"

elif [[ $runtime == python* ]]; then
  package_folder="python/lib/$runtime/site-packages/"
  mkdir -p "$output_folder/$package_folder"
  
  if [[ -n "$manifest" ]]; then
    echo "Copying manifest file to $output_folder/requirements.txt"
    cp "$manifest" "$output_folder/requirements.txt"
    testpath="$output_folder/requirements.txt"
    chmod 0644 "$testpath"
    echo "Contents of $testpath:"
    cat "$testpath"
  else
    echo "Creating an empty requirements.txt file"
    touch "$output_folder/requirements.txt"
    chmod 0644 "$output_folder/requirements.txt"
  fi

  echo "Install command: $install_command"
  install_command="pip install -r /layer/requirements.txt -t /layer/$package_folder $packages"
  echo "Install command after update: $install_command"
  volume_params="$volume_params -v $HOME/.config/pip:/root/.config/pip -v $output_folder/requirements.txt:/layer/requirements.txt:ro"

else
  usage
  exit 1
fi

echo "Building layer"
zip_command="zip -r layer.zip python"
docker run --rm $volume_params -w "/layer" "$docker_image" /bin/bash -c "$install_command && $zip_command"

pushd "$output_folder"
echo "Uploading layer $name to AWS"
aws lambda publish-layer-version --layer-name "$name" --compatible-runtimes "$runtime" --zip-file "fileb://layer.zip"
echo "Upload complete"
popd

echo "Cleaning up"
rm -rf "$output_folder"

echo "All done. Enjoy your shiny new Lambda layer!"