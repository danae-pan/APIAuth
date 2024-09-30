using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;

public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string Id { get; set; }

    [BsonElement("Username")]
    public string Username { get; set; }

    [BsonElement("PasswordHash")]
    public string PasswordHash { get; set; }

    [BsonElement("Roles")] 
    public List<string> Roles { get; set; } = new List<string>(); // Default to an empty list
}
