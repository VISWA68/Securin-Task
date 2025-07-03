from flask import Flask, request, jsonify
from flask_cors import CORS
from flask_pymongo import PyMongo
import datetime
import xml.etree.ElementTree as ET

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

#get_cpe_data()

@app.route("/get_by_title", methods=["GET"])
def get_by_title():
    search = request.args.get("search_by")
    val = request.args.get("value")
    try:
        item = mongo.db.cpe.find_one({f"{search}": val})
        if not item:
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
    
@app.route("/get_by_title", methods=["GET"])
def get_by_title():
    search = request.args.get("search_by")
    val = request.args.get("value")
    try:
        item = mongo.db.cpe.find_one({f"{search}": val})
        if not item:
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)
