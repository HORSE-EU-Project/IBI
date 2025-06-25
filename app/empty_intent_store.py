from database import es_client
from elasticsearch.exceptions import NotFoundError

def _clear_index(index_name):
    """Helper function to delete all documents from an index if it exists."""
    try:
        # Use es.indices.exists to check for an index, not es.exists which checks for a document.
        if es_client.indices.exists(index=index_name):
            # Use delete_by_query for efficiency. It's a single request.
            es_client.delete_by_query(
                index=index_name,
                query={"match_all": {}},
                refresh=True,
                conflicts='proceed' # Continue even if there are version conflicts
            )
            print(f"Cleared all documents from index '{index_name}'.")
    except NotFoundError:
        # This can happen in a race condition if index is deleted between exists() and delete_by_query()
        print(f"Index '{index_name}' not found, skipping clear.")
    except Exception as e:
        print(f"An error occurred while clearing index '{index_name}': {e}")

def empty_fun():
    """
    Deletes all documents from specified Elasticsearch indices.
    This is intended to be run at the start of a new deployment to ensure a clean state.
    """
    indices_to_clear = [
        "stored_intents",
        "awaiting_intents",
        "stored_qos_intents"
    ]
    for index in indices_to_clear:
        _clear_index(index)