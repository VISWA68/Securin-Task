from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
import datetime
import xml.etree.ElementTree as ET
from bson import json_util, ObjectId
import json

app = Flask(__name__)
CORS(app)

app.config["MONGO_URI"] = "mongodb+srv://v:viswa123@cluster0.dhc4mq5.mongodb.net/securin?retryWrites=true&w=majority"
mongo = PyMongo(app)

tree = ET.parse('official-cpe-dictionary_v2.3.xml')
root = tree.getroot()

namespaces = {
    'cpe': 'http://cpe.mitre.org/dictionary/2.0',
    'cpe-23': 'http://scap.nist.gov/schema/cpe-extension/2.3'
}

def add_data(title, uri22, uri23, links, date_22, date23):
    return {
        "cpe_title": title,
        "cpe_22_uri": uri22,
        "cpe_23_uri": uri23,
        "reference_links": links,
        "cpe_22_deprecation_date": date_22,
        "cpe_23_deprecation_date": date23
    }

def get_cpe_data():
    cpe_data = []
    for item in root.findall('cpe:cpe-item', namespaces):
        title_elem = item.find('cpe:title', namespaces)
        title = title_elem.text if title_elem is not None else None
        uri22 = item.get('name')
        cpe23_elem = item.find('cpe-23:cpe23-item', namespaces)
        uri23 = cpe23_elem.get('name') if cpe23_elem is not None else None
        links = []
        for ref in item.findall('.//cpe:reference', namespaces):
            links.append(ref.get('href'))
        date_22 = None
        date23 = None
        data = add_data(title, uri22, uri23, links, date_22, date23)
        cpe_data.append(data)
    print(f"Total items parsed: {len(cpe_data)}")
    insert_data(cpe_data)

def insert_data(cpe_data):
    if cpe_data:
        mongo.db.cpe.insert_many(cpe_data)
        print(f"Inserted {len(cpe_data)} items into the database.")
    else:
        print("No data to insert.")

#get_cpe_data()  RUN THIS ONLY FOR THE FIRST TIME

def comma_separated_params_to_list(param):
    result = []
    for val in param.split(','):
        if val:
            result.append(val)
    return result

@app.route("/search_data", methods=["GET"])
def search():
    search_data = {}

    params = request.args.getlist('search') or request.form.getlist('search')
    if len(params) == 1 and ',' in params[0]:
        search_data['search'] = comma_separated_params_to_list(params[0])
    else:
        search_data['search'] = params
    
    params = request.args.getlist('value') or request.form.getlist('value')
    if len(params) == 1 and ',' in params[0]:
        search_data['value'] = comma_separated_params_to_list(params[0])
    else:
        search_data['value'] = params

    s = search_data['search']
    v = search_data['value']

    try:
        previous = mongo.db.cpe.find_one({f"{s[0]}": v[0]})
        if not previous:
                return jsonify({"error": "item not found"}), 404
        
        for i in range(len(s)):
            search = s[i]
            val = v[i]
            item = mongo.db.cpe.find_one({f"{search}": val})
            if not item or item != previous:
                return jsonify({"error": "item not found"}), 404
        
        links = []
        for i in item.get("reference_links", []):
            links.append(i)

        return jsonify({
            "cpe_title": item["cpe_title"],
            "cpe_22_uri":item["cpe_22_uri"],
            "cpe_23_uri": item["cpe_23_uri"],
            "reference_links": links,
            "cpe_22_deprecation_date": item["cpe_22_deprecation_date"],
            "cpe_23_deprecation_date": item["cpe_23_deprecation_date"]
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500
    
@app.route("/pagination", methods=["GET"])
def pagination():
    page = int(request.args.get("page")) if request.args.get("page") else 1
    limit = int(request.args.get("limit")) if request.args.get("limit") else 10
    cnt = (page - 1) * limit
    try:
        data = list(mongo.db.cpe.find().skip(cnt).limit(int(limit)))
        final = json.loads(json_util.dumps(data))
        return jsonify({
            "page": page,
            "limit": limit,
            "data": final
        }), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
