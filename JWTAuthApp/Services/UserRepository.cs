using MongoDB.Driver;

public class UserRepository
{
    private readonly MongoDbService _mongoDbService;
    private readonly IMongoCollection<User> _users;

    public UserRepository(MongoDbService mongoDbService)
    {
        _mongoDbService = mongoDbService;
        _users = _mongoDbService.GetCollection<User>("Users");
    }

    public async Task<User> GetUserByUsernameAsync(string username)
    {
        return await _users.Find(u => u.Username == username).FirstOrDefaultAsync();
    }

    public async Task CreateUserAsync(User user)
    {
        await _users.InsertOneAsync(user);
    }

    // Add a role to a user
    public async Task AddRoleAsync(string username, string role)
    {
        var update = Builders<User>.Update.AddToSet(u => u.Roles, role);
        await _users.UpdateOneAsync(u => u.Username == username, update);
    }

    // Remove a role from a user
    public async Task RemoveRoleAsync(string username, string role)
    {
        var update = Builders<User>.Update.Pull(u => u.Roles, role);
        await _users.UpdateOneAsync(u => u.Username == username, update);
    }
}
