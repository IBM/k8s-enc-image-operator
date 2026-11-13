#! /bin/bash

set +x 

GOSRCFILES=($(find . -name "*.go"))
THISYEAR=$(date +"%Y")

for GOFILE in "${GOSRCFILES[@]}"; do
  # If no copyright at all
  if ! grep -q "Licensed under the Apache License, Version 2.0" $GOFILE; then
    echo "// Copyright ${THISYEAR} k8s-enc-image-operator authors.
//
// Licensed under the Apache License, Version 2.0 (the \"License\");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an \"AS IS\" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
$(cat ${GOFILE})" > ${GOFILE}
   fi    
done

# Check for multi-line in new files
GOSRCFILES=($(git diff --name-only origin/master | grep '\.go$'))
for GOFILE in "${GOSRCFILES[@]}"; do
  if grep -q "Copyright .* k8s-enc-image-operator authors." $GOFILE; then
      YEAR_LINE=$(grep "Copyright .* k8s-enc-image-operator authors." $GOFILE)
      YEARS=($(echo $YEAR_LINE | grep -oE '[0-9]{4}'))
      if [[ ${#YEARS[@]} == 1 ]]; then
         if [[ ${YEARS[0]} != ${THISYEAR} ]]; then
            sed -i.bak -e "s|Copyright ${YEARS[0]} k8s-enc-image-operator authors.|Copyright ${YEARS[0]}, ${THISYEAR} k8s-enc-image-operator authors.|" "$GOFILE" && rm -f "$GOFILE.bak"
         fi
      elif [[ ${#YEARS[@]} == 2 ]]; then
        if [[ ${YEARS[1]} != ${THISYEAR} ]]; then
            sed -i.bak -e "s|Copyright ${YEARS[0]}, ${YEARS[1]} k8s-enc-image-operator authors.|Copyright ${YEARS[0]}, ${THISYEAR} k8s-enc-image-operator authors.|" "$GOFILE" && rm -f "$GOFILE.bak"
        fi
      fi
  fi
done
