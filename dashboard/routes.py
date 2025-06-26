from flask import Blueprint, render_template, request, jsonify, Response
from pymongo import MongoClient
import csv
import io
import os
from datetime import datetime
import re
from flask import redirect, url_for



bp = Blueprint('main', __name__)

# Initialize MongoDB client
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
client = MongoClient(MONGO_URI)
db = client.get_database('ctidb')
collection = db.get_collection('cti_records')

@bp.route('/')
def index():
    # Option A: render the home template straight away
    return render_template('home.html')

@bp.route('/home')
def home():
    """Render the home page"""
    return render_template('home.html')

@bp.route('/lookup')
def lookup_page():
    """Render the IOC lookup page"""
    return render_template('lookup.html')

@bp.route('/trends')
def trends_page():
    """Render the trends/findings page"""
    return render_template('trends.html')

@bp.route('/export')
def export_page():
    """Render the export page"""
    return render_template('export.html')

@bp.route('/api/ioc/<typ>/<value>')
def api_ioc(typ, value):
    # Validate domain format
    if typ == 'domain' and '.' not in value:
        return jsonify({'error': 'Invalid domain format'}), 400

    # Validate IP format
    if typ == 'ip' and not re.match(r'^\d{1,3}(\.\d{1,3}){3}$', value):
        return jsonify({'error': 'Invalid IP format'}), 400

    # Validate hash format
    if typ == 'hash' and not re.match(r'^[a-fA-F0-9]{32,64}$', value):
        return jsonify({'error': 'Invalid hash format'}), 400

    # Query database
    if typ == 'domain':
        record = collection.find_one({
            'type': typ,
            'ioc': {'$regex': f'^{re.escape(value)}$', '$options': 'i'}
        })
    else:
        record = collection.find_one({'type': typ, 'ioc': value})
    if not record:
        return jsonify({'error': 'IOC not found'}), 404
    # ✅ FIX: Handle missing VT data
    if 'vt' not in record:
        record['vt'] = {'data': {'attributes': {'last_analysis_stats': {'malicious': 0}}}}

    # Serialize ObjectId and datetime fields for JSON
    record['_id'] = str(record['_id'])
    if 'first_seen' in record:
        record['first_seen'] = record['first_seen'].isoformat()
    if 'last_updated' in record:
        record['last_updated'] = record['last_updated'].isoformat()

    return jsonify(record)


@bp.route('/api/tag', methods=['POST'])
def api_tag():
    """Tag an IOC record"""
    data = request.get_json()
    typ = data.get('type')
    ioc = data.get('ioc')
    tag = data.get('tag')
    if not all([typ, ioc, tag]):
        return jsonify({'error': 'Missing fields'}), 400
    result = collection.update_one(
        {'type': typ, 'ioc': ioc},
        {'$addToSet': {'tags': tag}}
    )
    if result.matched_count == 0:
        return jsonify({'error': 'IOC not found'}), 404
    return jsonify({'status': 'tag added'})

@bp.route('/api/summary')
def api_summary():
    """Return aggregated daily counts and avg malicious score"""
    date_from = request.args.get('date_from')
    date_to = request.args.get('date_to')
    match = {}
    if date_from:
        match['last_updated'] = {'$gte': datetime.fromisoformat(date_from)}
    if date_to:
        to_dt = datetime.fromisoformat(date_to)
        match.setdefault('last_updated', {})['$lte'] = to_dt

    pipeline = []
    if match:
        pipeline.append({'$match': match})
    pipeline.extend([
        {'$group': {
            '_id': {
                '$dateToString': {'format': '%Y-%m-%d', 'date': '$last_updated'}
            },
            'count': {'$sum': 1},
            'avg_vt_score': {'$avg': '$vt.data.attributes.last_analysis_stats.malicious'}
        }},
        {'$sort': {'_id': 1}}
    ])
    data = list(collection.aggregate(pipeline))
    return jsonify(data)

@bp.route('/api/findings')
def api_findings():
    """Return recent high-severity IOCs"""
    severity = request.args.get('severity', 'high')
    thresh = 5 if severity == 'high' else 1
    cursor = collection.find({'vt.data.attributes.last_analysis_stats.malicious': {'$gte': thresh}})
    cursor = cursor.sort('last_updated', -1).limit(20)
    results = []
    for rec in cursor:
        results.append({
            'ioc': rec['ioc'],
            'type': rec['type'],
            'last_updated': rec['last_updated'].isoformat(),
            'vt': rec.get('vt', {})
        })
    return jsonify(results)

@bp.route('/api/export')
def api_export():
    """Export all records as CSV or JSON"""
    fmt = request.args.get('format', 'json')
    cursor = collection.find()
    if fmt == 'csv':
        def generate():
            output = io.StringIO()
            writer = csv.writer(output)
            writer.writerow(['ioc', 'type', 'first_seen', 'last_updated', 'malicious'])
            yield output.getvalue()
            output.seek(0)
            output.truncate(0)
            for rec in cursor:
                writer.writerow([
                    rec['ioc'], rec['type'],
                    rec['first_seen'].isoformat(),
                    rec['last_updated'].isoformat(),
                    rec.get('vt', {}).get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
                ])
                yield output.getvalue()
                output.seek(0)
                output.truncate(0)
        return Response(
            generate(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=cti_export.csv'}
        )
    # JSON
    results = []
    for rec in cursor:
        rec['_id'] = str(rec['_id'])
        rec['first_seen'] = rec['first_seen'].isoformat()
        rec['last_updated'] = rec['last_updated'].isoformat()
        results.append(rec)
    return jsonify(results)
