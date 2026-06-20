import { QdrantClient } from '@qdrant/js-client-rest';

const qdrantUrl = process.env.QDRANT_URL || 'http://localhost:6333';
export const qdrant = new QdrantClient({ url: qdrantUrl });

export async function initQdrantCollections() {
  console.log("[Qdrant Startup] Connecting to Qdrant vector database...");
  try {
    // Probe connection using getCollections
    const currentCollectionsResponse = await qdrant.getCollections().catch(() => null);
    if (!currentCollectionsResponse) {
      console.warn("[Qdrant Warning] Qdrant service is not reachable. RAG search will degrade.");
      return;
    }

    const collections = ['knowledge_base', 'alert_rules', 'incidents', 'logs'];
    const currentNames = currentCollectionsResponse.collections.map(c => c.name);

    for (const name of collections) {
      if (!currentNames.includes(name)) {
        await qdrant.createCollection(name, {
          vectors: {
            size: 1536, // Standard embedding dimension (e.g. text-embedding-3-small)
            distance: 'Cosine'
          }
        });
        console.log(`[Qdrant Startup] Created Vector Collection: ${name}`);
      }
    }
    console.log("[Qdrant Startup] Qdrant collections initialized.");
  } catch (err: any) {
    console.warn("[Qdrant Warning] Qdrant initialization failed. Error:", err.message);
  }
}
export default qdrant;
