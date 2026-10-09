from typing import List, Dict, Any
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from app.rag.kb_data import OWASP_CWE_KNOWLEDGE_BASE

class RAGVectorStore:
    """
    RAG Knowledge Retrieval Engine using TF-IDF & Cosine Similarity vector search.
    Provides fast, deterministic security context retrieval for OWASP Top 10 & CWEs.
    """

    def __init__(self):
        self.kb_items = OWASP_CWE_KNOWLEDGE_BASE
        self.documents = [
            f"{item['owasp_id']} {item['cwe_id']} {item['title']} {item['description']} {item['impact']} {item['mitigation']}"
            for item in self.kb_items
        ]
        self.vectorizer = TfidfVectorizer(stop_words='english')
        if self.documents:
            self.doc_vectors = self.vectorizer.fit_transform(self.documents)
        else:
            self.doc_vectors = None

    def search(self, query: str, top_k: int = 3) -> List[Dict[str, Any]]:
        if not self.documents or not query.strip():
            return self.kb_items[:top_k]

        try:
            query_vector = self.vectorizer.transform([query])
            similarities = cosine_similarity(query_vector, self.doc_vectors).flatten()

            top_indices = similarities.argsort()[::-1][:top_k]
            results = []
            for idx in top_indices:
                item = dict(self.kb_items[idx])
                item["similarity_score"] = float(round(similarities[idx], 4))
                results.append(item)
            return results
        except Exception:
            return self.kb_items[:top_k]

    def get_by_cwe(self, cwe_id: str) -> Dict[str, Any]:
        cwe_clean = cwe_id.upper().strip()
        for item in self.kb_items:
            if item["cwe_id"].upper() == cwe_clean:
                return item
        return self.search(cwe_id, top_k=1)[0]

rag_vector_store = RAGVectorStore()
