const { MongoClient } = require('mongodb');
const crypto = require('crypto');

function hashPassword(password) {
  return crypto.createHash('sha256').update(password).digest('hex');
}

async function cleanAll() {
  const uri = 'mongodb+srv://ashishyadav14065_db_user:vyONlYEINPa4T1Qt@cluster0.r51zmz3.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0';
  const client = new MongoClient(uri);
  await client.connect();
  const db = client.db('teamsarkar_db');
  
  const collections = ['matches', 'tournaments', 'practices', 'notes', 'players', 'team_stats', 'sync', 'user_data'];
  for (const c of collections) {
    const res = await db.collection(c).deleteMany({});
    console.log(`Deleted ${res.deletedCount} from ${c}`);
  }

  // Clear users and seed ONLY ASHISH800 with password ASHISH8006
  await db.collection('users').deleteMany({});
  const masterUser = {
    userId: 'ASHISH800',
    name: 'Ashish Sarkar',
    email: 'ashish800@teamsarkar.com',
    passwordHash: hashPassword('ASHISH8006'),
    role: 'IGL',
    isMaster: true,
    createdAt: new Date()
  };
  await db.collection('users').insertOne(masterUser);
  console.log('MongoDB reset complete. Only ASHISH800 (password: ASHISH8006) exists.');

  const remainingUsers = await db.collection('users').find({}).toArray();
  console.log('Remaining users:', remainingUsers.map(u => ({ userId: u.userId, role: u.role, isMaster: u.isMaster })));
  await client.close();
}

cleanAll().catch(console.error);
