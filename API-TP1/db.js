const mysql = require('mysql');

// Connexion à la base de données MySQL
connection = mysql.createConnection({
    host: 'localhost',
    user: 'todolist',
    password: 'todolist',
    database: 'todolist'
});

connection.connect((err) => {
    if (err) {
        console.error('Erreur de connexion à la base de données :', err);
        throw err;
    }
    console.log('Connecté à la base de données MySQL');
});

module.exports = connection;