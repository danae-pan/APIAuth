using MongoDB.Driver;

public class MongoDbService
{
    private readonly IMongoDatabase _db;

    public MongoDbService(IConfiguration configuration)
    {
        // Retrieve the MongoDB connection string from configuration
        var connectionString = configuration["MongoDB:ConnectionString"];
        if (string.IsNullOrEmpty(connectionString))
        {
            throw new ArgumentNullException(nameof(connectionString), "MongoDB connection string is missing.");
        }

        // Retrieve the database name from the configuration
        var databaseName = configuration["MongoDB:DatabaseName"];
        if (string.IsNullOrEmpty(databaseName))
        {
            throw new ArgumentNullException(nameof(databaseName), "MongoDB database name is missing.");
        }

        var client = new MongoClient(connectionString);
        _db = client.GetDatabase(databaseName);
    }

    public IMongoCollection<T> GetCollection<T>(string name)
    {
        return _db.GetCollection<T>(name);
    }
}


