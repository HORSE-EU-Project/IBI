import time
from db.elastic_search import es_client as es

def delete_and_reindex(id_to_delete, index):
    """
    Deletes a document and then attempts to re-index all documents
    to have sequential IDs.

    NOTE: This re-indexing logic is highly inefficient and not recommended
    for production systems. It fetches up to 100 documents, deletes them,
    and re-inserts them. This is prone to race conditions and data loss if
    more than 100 documents exist. Elasticsearch document _id fields are not
    meant to be sequential. Consider using a separate field for ordering if needed.
    """
    es.delete(index=index, id=id_to_delete)
    time.sleep(1) # This sleep might be to allow ES to process the delete.

    # The following logic is preserved from the original but is not robust.
    resp = es.search(index=index, size=100, query={"match_all": {}})

    docs = [hit for hit in resp['hits']['hits']]

    # Delete all documents that were fetched
    for doc in docs:
        es.delete(index=index, id=doc['_id'])

    # Re-index them with sequential IDs
    for i, doc in enumerate(docs):
        source = doc['_source']
        if index != 'awaiting_intents':
            source['id'] = i + 1
        es.index(index=index, id=str(i + 1), document=source)

# The original file had two identical functions. They have been merged into one
# and given a more descriptive name. The old names are kept for compatibility.
delete_intents_elasticsearch_fun = delete_and_reindex
delete_intents_elasticsearch_fun_qos = delete_and_reindex