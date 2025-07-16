#
# Copyright 2025 University of Southern California
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
from flask import Blueprint, Response, current_app

metrics_blueprint = Blueprint("metrics", __name__)

@metrics_blueprint.route("/metrics")
def metrics():
    store = current_app.config["GROUP_STORAGE"]
    total_groups = len(store.list_groups())

    out = [
        "# HELP group_total Total Groups",
        "# TYPE group_total gauge",
        f"group_total {total_groups}"
    ]

    return Response("\n".join(out) + "\n", mimetype="text/plain")

