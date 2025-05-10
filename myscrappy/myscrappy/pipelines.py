from itemadapter import ItemAdapter
import pymongo
from datetime import datetime

class PhishingDetectionPipeline:
    def __init__(self):
        self.mongo_client = pymongo.MongoClient("mongodb://localhost:27018/")
        self.db = self.mongo_client["scrapy_db"]
        self.collection = self.db["bank_websites"]
        
        # Create indexes for better performance
        self.collection.create_index([("hash", pymongo.ASCENDING)], unique=True)
        self.collection.create_index([("url", pymongo.ASCENDING)])
        self.collection.create_index([("is_phishing", pymongo.ASCENDING)])

    def process_item(self, item, spider):
        adapter = ItemAdapter(item)
        
        # Add timestamp
        adapter['crawled_at'] = datetime.utcnow()
        
        # Save to MongoDB
        try:
            self.collection.update_one(
                {"hash": adapter['hash']},
                {"$set": dict(adapter)},
                upsert=True
            )
            spider.logger.info(f"✅ Saved to MongoDB: {adapter['url']} | Status: {adapter['is_phishing']}")
        except pymongo.errors.DuplicateKeyError:
            spider.logger.info(f"⚠️ Document already exists: {adapter['url']}")
        except Exception as e:
            spider.logger.error(f"❌ MongoDB Error: {e}")
            
        return item

    def close_spider(self, spider):
        self.mongo_client.close()
