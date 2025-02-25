from server import config
from server import data_stream

from fastapi import FastAPI, HTTPException

from server.algos import algos
from server.data_filter import operations_callback

import logging
from server.logger import logger

app = FastAPI()
# TODO drop commmented Flask code once FastHTML is tested
# app = Flask(__name__)
#

# TODO is threadng the right way to go here?
stream_stop_event = threading.Event()
stream_thread = threading.Thread(
    target=data_stream.run,
    args=(
        config.SERVICE_DID,
        operations_callback,
        stream_stop_event,
    ),
)
stream_thread.start()


def sigint_handler(*_):
    print("Stopping data stream...")
    stream_stop_event.set()
    sys.exit(0)


signal.signal(signal.SIGINT, sigint_handler)


# @app.route('/')
# def index():
#    return 'ATProto Feed Generator powered by The AT Protocol SDK for Python (https://github.com/MarshalX/atproto).'


@app.get("/")
async def index():
    return {
        "message": "ATProto Feed Generator powered by The AT Protocol SDK for Python (https://github.com/MarshalX/atproto)"
    }


#
# @app.route('/.well-known/did.json', methods=['GET'])
# def did_json():
#    if not config.SERVICE_DID.endswith(config.HOSTNAME):
#        return '', 404
#
#    return jsonify({
#        '@context': ['https://www.w3.org/ns/did/v1'],
#        'id': config.SERVICE_DID,
#        'service': [
#            {
#                'id': '#bsky_fg',
#                'type': 'BskyFeedGenerator',
#                'serviceEndpoint': f'https://{config.HOSTNAME}'
#            }
#        ]
#    })


@app.get("/.well-known/did.json")
async def did_json():
    if not config.SERVICE_DID.endswith(config.HOSTNAME):
        raise HTTPException(status_code=404)
    return {
        "@context": ["https://www.w3.org/ns/did/v1"],
        "id": config.SERVICE_DID,
        "service": [
            {
                "id": "#bsky_fg",
                "type": "BskyFeedGenerator",
                "serviceEndpoint": f"https://{config.HOSTNAME}",
            }
        ],
    }


# @app.route('/xrpc/app.bsky.feed.describeFeedGenerator', methods=['GET'])
# def describe_feed_generator():
#    feeds = [{'uri': uri} for uri in algos.keys()]
#    response = {
#        'encoding': 'application/json',
#        'body': {
#            'did': config.SERVICE_DID,
#            'feeds': feeds
#        }
#    }
#    return jsonify(response)


@app.get("/xrpc/app.bsky.feed.describeFeedGenerator")
async def describe_feed_generator():
    feeds = [{"uri": uri} for uri in algos.keys()]
    response = {
        "encoding": "application/json",
        "body": {"did": config.SERVICE_DID, "feeds": feeds},
    }
    return response


# @app.route('/xrpc/app.bsky.feed.getFeedSkeleton', methods=['GET'])
# def get_feed_skeleton():
#    feed = request.args.get('feed', default=None, type=str)
#    algo = algos.get(feed)
#    if not algo:
#        return 'Unsupported algorithm', 400
#
#    # Example of how to check auth if giving user-specific results:
#    """
#    from server.auth import AuthorizationError, validate_auth
#    try:
#        requester_did = validate_auth(request)
#    except AuthorizationError:
#        return 'Unauthorized', 401
#    """
#
#    try:
#        cursor = request.args.get('cursor', default=None, type=str)
#        limit = request.args.get('limit', default=20, type=int)
#        body = algo(cursor, limit)
#    except ValueError:
#        return 'Malformed cursor', 400
#
#    return jsonify(body)


@app.get("/xrpc/app.bsky.feed.getFeedSkeleton")
async def get_feed_skeleton(
    feed: str | None = None, cursor: str | None = None, limit: int = 20
):
    algo = algos.get(feed)
    if not algo:
        raise HTTPException(status_code=400, detail="Unsupported algorithm")

    # Example of how to check auth if giving user-specific results:
    # TODO check if this is needed or has to be recoded
    """
    from server.auth import AuthorizationError, validate_auth
    try:
        requester_did = validate_auth(request)
    except AuthorizationError:
        return 'Unauthorized', 401
    """
    try:
        body = algo(cursor, limit)
    except ValueError:
        raise HTTPException(status_code=400, detail="Malformed cursor")
    return body


if __name__ == "__main__":
    # FOR DEBUG PURPOSE ONLY
    logger.setLevel(logging.DEBUG)
    # app.run(host="127.0.0.1", port=8000, debug=True)
