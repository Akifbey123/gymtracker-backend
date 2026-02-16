import { Hono } from 'hono'
import { cors } from 'hono/cors'
import mongoose from 'mongoose'
import Groq from 'groq-sdk'
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'
import { v4 as uuidv4 } from 'uuid'
import { env } from 'hono/adapter'

const app = new Hono()

// Middleware
app.use('/*', cors())

// Constants & Env Helpers
const getEnv = (c, key) => c?.env?.[key] || process.env[key]

// --- MONGODB CONNECTION ---
// Note: In a Worker environment, it's best to handle connection caching.
const connectDB = async (env) => {
    // Check if already connected
    if (mongoose.connection.readyState === 1) return;

    // Use env var or fallback to the hardcoded string from original code (though env var is recommended)
    const mongoUrl = env?.MONGODB_URI || process.env.MONGODB_URI

    try {
        await mongoose.connect(mongoUrl);
        console.log("MongoDB veritabanına bağlandı!");
    } catch (err) {
        console.error("Bağlantı hatası:", err);
        throw err;
    }
};

// Middleware to ensure DB connection and inject clients
app.use('*', async (c, next) => {
    try {
        await connectDB(c.env);
    } catch (e) {
        return c.json({ message: "Database connection failed" }, 500);
    }
    await next();
});

// --- USER MODEL (SCHEMA) ---
const UserSchema = new mongoose.Schema({
    fullName: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    profilePhoto: { type: String },
    height: { type: Number },
    weight: { type: Number },
    bodyFat: { type: Number },
    activityLevel: { type: Number },
    goals: [{ type: String }],
    water: { type: Number, default: 0 },
    waterLogs: [{
        date: { type: String },
        amount: { type: Number, default: 0 }
    }],
    program: { type: Object },
    meals: [{
        food_name: String,
        calories: Number,
        protein: Number,
        carbs: Number,
        fat: Number,
        sugar: Number,
        period: String,
        date: { type: Date, default: Date.now }
    }],
    workoutLogs: [{
        date: { type: Date, default: Date.now },
        day: String,
        exercise: String,
        sets: [{
            reps: { type: Number, required: true },
            weight: { type: Number, required: true },
        }]
    }],
    daily_stats: {
        date: String,
        steps: Number,
        calories: Number,
        last_sync: Date
    },
    chatHistory: [{
        role: { type: String, enum: ['user', 'assistant'] },
        content: String,
        timestamp: { type: Date, default: Date.now }
    }]
});
const ExerciseSchema = new mongoose.Schema({
    name: { type: String, required: true },
    description: { type: String },
    muscleGroup: { type: String },
    difficulty: { type: String },
    videoUrl: { type: String },
    imageUrl: { type: String }
});
const User = mongoose.models.User || mongoose.model('User', UserSchema);
const Exercise = mongoose.models.Exercise || mongoose.model('Exercise', ExerciseSchema);

// Leaderboard Endpoint
app.get('/leaderboard', async (c) => {
    try {
        const exerciseName = c.req.query('exercise');
        const limit = parseInt(c.req.query('limit')) || 10;

        const pipeline = [
            // 1. Unwind logs
            { $unwind: "$workoutLogs" },
            // 2. Unwind sets
            { $unwind: "$workoutLogs.sets" }
        ];

        // 3. Filter by exercise if provided
        if (exerciseName) {
            pipeline.push({
                $match: { "workoutLogs.exercise": exerciseName }
            });
        }

        // 4. Group by User and Exercise (find max weight)
        pipeline.push(
            {
                $group: {
                    _id: {
                        userId: "$_id",
                        exercise: "$workoutLogs.exercise"
                    },
                    name: { $first: "$fullName" }, // Assuming fullName is the field
                    avatar: { $first: "$profilePhoto" }, // Assuming profilePhoto field
                    maxWeight: { $max: "$workoutLogs.sets.weight" },
                    date: { $first: "$workoutLogs.date" } // Just taking one date
                }
            },
            // 5. Sort by max weight descending
            { $sort: { maxWeight: -1 } },
            // 6. Limit (per exercise if grouping, or total list)
            // If filtering by specific exercise, limit directly.
            // If fetching global leaderboard across all exercises, we might want top X per exercise.
            // For now, let's assume filtering -> simple limit.
            // If no filter -> maybe group by exercise again?
        );

        if (exerciseName) {
            pipeline.push(
                { $limit: limit },
                {
                    $project: {
                        _id: 0,
                        userId: "$_id.userId",
                        name: 1,
                        avatar: 1,
                        weight: "$maxWeight",
                        date: 1
                    }
                }
            );
        } else {
            // Global Leaderboard: Group by Exercise
            pipeline.push(
                {
                    $group: {
                        _id: "$_id.exercise",
                        topAthletes: {
                            $push: {
                                userId: "$_id.userId",
                                name: "$name",
                                avatar: "$avatar",
                                weight: "$maxWeight",
                                date: "$date"
                            }
                        }
                    }
                },
                {
                    // Sort inside the arrays (optional, already sorted by input stream but pushing might lose order?)
                    // Best to just unwind and sort again or slice first?
                    // To keep it simple: just return whatever we have, client can filter.
                    $project: {
                        exercise: "$_id",
                        topAthletes: { $slice: ["$topAthletes", limit] }, // Top X per exercise
                        _id: 0
                    }
                }
            );
        }

        const leaderboard = await User.aggregate(pipeline);
        return c.json(leaderboard);

    } catch (error) {
        console.error("Leaderboard Error:", error);
        return c.json({ message: "Sıralama verisi alınamadı." }, 500);
    }
});


// --- HELPER CLIENTS ---
const getR2Client = (c) => {
    const accessKeyId = getEnv(c, 'R2_ACCESS_KEY_ID');
    const secretAccessKey = getEnv(c, 'R2_SECRET_ACCESS_KEY');
    const accountId = getEnv(c, 'R2_ACCOUNT_ID');

    if (!accessKeyId || !secretAccessKey || !accountId) return null;

    return new S3Client({
        region: 'auto',
        endpoint: `https://${accountId}.r2.cloudflarestorage.com`,
        credentials: { accessKeyId, secretAccessKey },
    });
};

const getGroqClient = (c) => {
    const apiKey = getEnv(c, 'GROQ_API_KEY');
    if (!apiKey) return null;
    return new Groq({ apiKey });
};

// --- ROUTES ---

// Update Meal Period
app.put('/update-meal-period', async (c) => {
    try {
        const { mealId, period, email } = await c.req.json();
        const user = await User.findOneAndUpdate(
            { email: email, 'meals._id': mealId },
            { $set: { 'meals.$.period': period } },
            { new: true }
        );
        if (user) {
            return c.json({ message: "Öğün güncellendi", success: true });
        } else {
            return c.json({ message: "Kullanıcı veya öğün bulunamadı" }, 404);
        }
    } catch (error) {
        console.error("Öğün güncelleme hatası:", error);
        return c.json({ message: "Sunucu hatası" }, 500);
    }
});

// Get Meals
app.get('/get-meals/:email', async (c) => {
    try {
        const email = c.req.param('email');
        const user = await User.findOne({ email });
        if (user) {
            const sortedMeals = [...user.meals].reverse();
            return c.json({ meals: sortedMeals });
        } else {
            return c.json({ message: "Kullanıcı bulunamadı" }, 404);
        }
    } catch (error) {
        console.error("Geçmiş çekilemedi:", error);
        return c.json({ message: "Sunucu hatası" }, 500);
    }
});

// Save Meal
app.post('/save-meal', async (c) => {
    try {
        const { email, mealData } = await c.req.json();
        const user = await User.findOneAndUpdate(
            { email: email },
            {
                $push: {
                    meals: {
                        ...mealData,
                        date: new Date()
                    }
                }
            },
            { new: true }
        );
        if (user) {
            return c.json({ message: "Yemek kaydedildi", success: true });
        } else {
            return c.json({ message: "Kullanıcı bulunamadı" }, 404);
        }
    } catch (error) {
        console.error("Yemek kaydetme hatası:", error);
        return c.json({ message: "Sunucu hatası" }, 500);
    }
});

// Delete Meal
app.delete('/delete-meal', async (c) => {
    try {
        const { email, mealId } = await c.req.json();
        const user = await User.findOneAndUpdate(
            { email: email },
            { $pull: { meals: { _id: mealId } } },
            { new: true }
        );
        if (user) {
            return c.json({ message: "Yemek silindi", success: true });
        } else {
            return c.json({ message: "Kullanıcı veya yemek bulunamadı" }, 404);
        }
    } catch (error) {
        console.error("Yemek silme hatası:", error);
        return c.json({ message: "Sunucu hatası" }, 500);
    }
});

// Analyze Image (Groq Vision)
app.post('/analyze-image', async (c) => {
    try {
        const groq = getGroqClient(c);
        if (!groq) return c.json({ message: "Yapay zeka özellikleri çalışmayacak (Missing API Key)." }, 500);

        const body = await c.req.parseBody();
        const imageFile = body['image'];

        if (!imageFile) {
            return c.json({ message: "Görüntü verisi gelmedi." }, 400);
        }

        const arrayBuffer = await imageFile.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);
        const mimeType = imageFile.type;
        const base64Image = `data:${mimeType};base64,${buffer.toString('base64')}`;

        const promptText = `
            ROL: Sen dünyanın en iyi beslenme uzmanı ve diyetisyenisin.
            GÖREV: Sana gönderilen yemek fotoğrafını analiz et.
            
            İSTENEN ÇIKTI (SADECE JSON):
            {
                "food_name": "Yemeğin İsmi",
                "calories": 0,
                "protein": 0,
                "carbs": 0,
                "sugar": 0,
                "fat": 0,
                "health_tip": "Tavsiye cümlesi",
                "calories_per_100g": 0
            }
            Sadece JSON döndür, yorum yapma.
        `;

        const chatCompletion = await groq.chat.completions.create({
            messages: [
                {
                    role: "user",
                    content: [
                        { type: "text", text: promptText },
                        { type: "image_url", image_url: { url: base64Image } }
                    ]
                }
            ],
            model: "meta-llama/llama-4-scout-17b-16e-instruct",
            temperature: 0.5,
            max_tokens: 1024,
            top_p: 1,
            stream: false
        });

        const aiResponseContent = chatCompletion.choices[0]?.message?.content || "Görüntü analiz edilemedi.";
        console.log("AI Ham Cevap:", aiResponseContent);

        let jsonResponse;
        try {
            const cleanJson = aiResponseContent.replace(/```json/g, "").replace(/```/g, "").trim();
            jsonResponse = JSON.parse(cleanJson);
        } catch (e) {
            console.error("JSON parse error", e);
            return c.json({ message: "AI cevabı okunamadı", raw: aiResponseContent }, 500);
        }

        return c.json({ result: jsonResponse });

    } catch (error) {
        console.error("Görüntü Analiz Hatası:", error);
        return c.json({ message: "Görüntü analiz edilirken hata oluştu.", error: error.message }, 500);
    }
});

// Save Log
app.post('/save-log', async (c) => {
    try {
        const { email, day, exercise, sets } = await c.req.json();

        // Validate sets format
        if (!Array.isArray(sets)) {
            return c.json({ message: "Sets must be an array of objects (e.g., [{reps: 10, weight: 20}])." }, 400);
        }
        const updatedUser = await User.findOneAndUpdate(
            { email: email },
            {
                $push: {
                    workoutLogs: {
                        day: day,
                        exercise: exercise,
                        sets: sets, // Expecting array of { reps, weight, rpe }
                        date: new Date()
                    }
                }
            },
            { new: true }
        );
        if (!updatedUser) return c.json({ message: "Kullanıcı bulunamadı" }, 404);
        return c.json({ message: "Kaydedildi", logs: updatedUser.workoutLogs });
    } catch (error) {
        console.error("Log hatası:", error);
        return c.json({ message: "Sunucu hatası" }, 500);
    }
});

// Update Water
app.post('/update-water', async (c) => {
    try {
        const { email, waterAmount } = await c.req.json();
        const today = new Date().toISOString().split('T')[0]; // "YYYY-MM-DD"

        const user = await User.findOne({ email });
        if (!user) return c.json({ message: "Kullanıcı bulunamadı" }, 404);

        // Update today's water (also keep the legacy field in sync)
        const existingLog = user.waterLogs.find(log => log.date === today);
        if (existingLog) {
            existingLog.amount = waterAmount;
        } else {
            user.waterLogs.push({ date: today, amount: waterAmount });
        }
        user.water = waterAmount; // keep legacy field in sync
        await user.save();

        return c.json({ message: "Su güncellendi", water: waterAmount, date: today });
    } catch (error) {
        console.error("Water update error:", error);
        return c.json({ message: "Hata oluştu" }, 500);
    }
});

// Get Water
app.get('/get-water/:email', async (c) => {
    try {
        const email = c.req.param('email');
        const user = await User.findOne({ email });
        if (!user) return c.json({ water: 0, history: [] });

        const today = new Date().toISOString().split('T')[0];
        const todayLog = user.waterLogs.find(log => log.date === today);

        return c.json({
            water: todayLog ? todayLog.amount : 0,
            history: user.waterLogs.slice(-30).reverse() // last 30 days
        });
    } catch (error) {
        return c.json({ message: "Hata oluştu" }, 500);
    }
});

// Google Fit Integration
async function getGoogleFitData(c) {
    try {
        const GOOGLE_CLIENT_ID = getEnv(c, 'GOOGLE_CLIENT_ID');
        const GOOGLE_CLIENT_SECRET = getEnv(c, 'GOOGLE_CLIENT_SECRET');
        const GOOGLE_REFRESH_TOKEN = getEnv(c, 'GOOGLE_REFRESH_TOKEN');

        if (!GOOGLE_CLIENT_ID || !GOOGLE_CLIENT_SECRET || !GOOGLE_REFRESH_TOKEN) {
            console.error("Google env vars missing");
            return null;
        }

        const tokenResponse = await fetch("https://oauth2.googleapis.com/token", {
            method: "POST",
            headers: { "Content-Type": "application/x-www-form-urlencoded" },
            body: new URLSearchParams({
                client_id: GOOGLE_CLIENT_ID,
                client_secret: GOOGLE_CLIENT_SECRET,
                refresh_token: GOOGLE_REFRESH_TOKEN,
                grant_type: "refresh_token",
            }),
        });

        console.log("CLIENT ID: ", GOOGLE_CLIENT_ID);
        console.log("CLIENT SECRET: ", GOOGLE_CLIENT_SECRET);
        console.log("REFRESH TOKEN: ", GOOGLE_REFRESH_TOKEN);

        const tokenData = await tokenResponse.json();
        console.log(tokenResponse)
        console.log(tokenData);
        if (!tokenResponse.ok) return null;

        const accessToken = tokenData.access_token;
        const now = new Date();
        const startOfDay = new Date(now.getFullYear(), now.getMonth(), now.getDate());
        const startMs = startOfDay.getTime();
        const endMs = now.getTime();

        const datasetResponse = await fetch(
            "https://www.googleapis.com/fitness/v1/users/me/dataset:aggregate",
            {
                method: "POST",
                headers: {
                    Authorization: `Bearer ${accessToken}`,
                    "Content-Type": "application/json",
                },
                body: JSON.stringify({
                    aggregateBy: [
                        { dataTypeName: "com.google.step_count.delta" },
                        { dataTypeName: "com.google.calories.expended" },
                    ],
                    bucketByTime: { durationMillis: 86400000 },
                    startTimeMillis: startMs,
                    endTimeMillis: endMs,
                }),
            }
        );
        console.log(datasetResponse);
        const fitData = await datasetResponse.json();
        console.log(fitData);
        if (!datasetResponse.ok) return null;

        let steps = 0;
        let calories = 0;

        if (fitData.bucket && fitData.bucket.length > 0) {
            fitData.bucket.forEach((bucket) => {
                if (bucket.dataset) {
                    bucket.dataset.forEach((dataset) => {
                        if (dataset.point) {
                            dataset.point.forEach((point) => {
                                if (point.value) {
                                    point.value.forEach((val) => {
                                        if (val.intVal) steps += val.intVal;
                                        if (val.fpVal) calories += val.fpVal;
                                    });
                                }
                            });
                        }
                    });
                }
            });
        }

        return {
            date: now.toISOString().split("T")[0],
            steps: steps,
            calories: Math.round(calories),
        };
    } catch (error) {
        console.error("Google Fit Entegrasyon Hatası:", error);
        return null;
    }
}

app.post("/sync-fitness-data", async (c) => {
    try {
        let email;
        try {
            const body = await c.req.json();
            email = body.email;
        } catch (e) {
            return c.json({ message: "Geçersiz istek gövdesi (JSON bekleniyor)." }, 400);
        }

        if (!email) {
            return c.json({ message: "Email adresi gerekli." }, 400);
        }
        const fitnessData = await getGoogleFitData(c);

        if (!fitnessData) {
            return c.json({ message: "Google Fit verisi alınamadı." }, 500);
        }

        const user = await User.findOneAndUpdate(
            { email: email },
            {
                $set: {
                    daily_stats: {
                        ...fitnessData,
                        last_sync: new Date()
                    }
                }
            },
            { new: true }
        );

        if (!user) {
            return c.json({ message: "Kullanıcı bulunamadı." }, 404);
        }

        return c.json({ status: "success", data: fitnessData, user });

    } catch (error) {
        console.error("Sync hatası:", error);
        return c.json({ message: "Sunucu hatası." }, 500);
    }
});

// Register
app.post('/register', async (c) => {
    try {
        const { fullName, email, password } = await c.req.json();
        const existingUser = await User.findOne({ email });
        if (existingUser) return c.json({ message: "Bu email zaten kayıtlı." }, 400);

        const newUser = new User({ fullName, email, password });
        await newUser.save();

        return c.json({ message: "Kayıt başarılı!" }, 201);
    } catch (error) {
        return c.json({ message: "Sunucu hatası oluştu." }, 500);
    }
});

// Login
app.post('/login', async (c) => {
    try {
        const { email, password } = await c.req.json();
        const user = await User.findOne({ email });
        if (!user) return c.json({ message: "Kullanıcı bulunamadı." }, 404);
        if (user.password !== password) return c.json({ message: "Şifre hatalı!" }, 401);

        const userObj = user.toObject();
        delete userObj.password;
        const goals = user.goals || [];
        userObj.filled = !!(user.height && user.weight && goals.length > 0);

        return c.json({
            message: "Giriş başarılı!",
            user: userObj
        });
    } catch (error) {
        return c.json({ message: "Sunucu hatası.", error: error.message }, 500);
    }
});

// Save User Info
app.post('/save-user-info', async (c) => {
    try {
        const { email, height, weight, bodyFat, activityLevel, goals } = await c.req.json();
        const user = await User.findOneAndUpdate(
            { email: email },
            { height, weight, bodyFat, activityLevel, goals },
            { new: true }
        );
        if (!user) return c.json({ message: "Kullanıcı bulunamadı." }, 404);
        return c.json({ message: "Bilgiler kaydedildi.", user });
    } catch (error) {
        return c.json({ message: "Sunucu hatası." }, 500);
    }
});

// Async R2 Upload helper
async function uploadToR2(c, buffer, key, contentType) {
    const r2 = getR2Client(c);
    const R2_BUCKET_NAME = getEnv(c, 'R2_BUCKET_NAME');
    const R2_PUBLIC_URL = getEnv(c, 'R2_PUBLIC_URL');

    if (!r2 || !R2_BUCKET_NAME) {
        throw new Error('R2 configuration missing.');
    }

    const command = new PutObjectCommand({
        Bucket: R2_BUCKET_NAME,
        Key: key,
        Body: buffer,
        ContentType: contentType,
    });

    await r2.send(command);

    const baseUrl = R2_PUBLIC_URL ? R2_PUBLIC_URL.replace(/\/$/, '') : '';
    const cleanKey = key.replace(/^\//, '');
    return `${baseUrl}/${cleanKey}`;
}

// Update Profile (Avatar) - WITH R2 STORAGE
app.post('/update-profile', async (c) => {
    try {
        const body = await c.req.parseBody();
        const email = body['email'];
        const fullName = body['fullName'];
        const profilePhoto = body['profilePhoto']; // Standard File object in Hono

        let updateData = { fullName };

        if (profilePhoto && typeof profilePhoto === 'object') {
            try {
                const arrayBuffer = await profilePhoto.arrayBuffer();
                const buffer = Buffer.from(arrayBuffer);
                const mimeType = profilePhoto.type;
                const ext = mimeType.split('/')[1] || 'jpg';
                const fileName = `avatars/avatar-${Date.now()}-${Math.floor(Math.random() * 1000)}.${ext}`;

                const publicUrl = await uploadToR2(c, buffer, fileName, mimeType);
                updateData.profilePhoto = publicUrl;
            } catch (uploadError) {
                console.error("R2 Upload failed:", uploadError);
                return c.json({ message: "Dosya yüklenemedi, R2 ayarlarını kontrol et.", error: uploadError.message }, 500);
            }
        }

        const user = await User.findOneAndUpdate(
            { email: email },
            { $set: updateData },
            { new: true }
        );

        if (!user) return c.json({ message: "Kullanıcı bulunamadı." }, 404);
        return c.json({ message: "Profil güncellendi.", user });

    } catch (error) {
        console.error("Profile update error", error)
        return c.json({ message: "Sunucu hatası.", error: error.message }, 500);
    }
});

// Generate Program
app.post('/generate-program', async (c) => {
    try {
        const { email, height, weight, goals, activityLevel } = await c.req.json();

        const prompt = `
            ANSWER MUST BE IN ENGLİSH LANGUAGE
            ROLE: You are an elite Military Fitness Instructor. You do NOT suggest. You COMMAND.
            TASK: Generate a strict, no-nonsense workout and nutrition plan in valid JSON format.
            USER PROFILE:
            - Height: ${height} cm
            - Weight: ${weight} kg
            - Goals: ${goals.join(", ")}
            - Frequency: ${activityLevel} days/week (You must provide exactly ${activityLevel} distinct workout days)
            CRITICAL RULES:
            1. LANGUAGE: Output MUST be in ENGLISH. 
            2. TONE: Imperative and strict.
            3. EXERCISES: Use standard gym terminology.
            4. FORMAT: Return ONLY valid JSON.
            JSON STRUCTURE:
            {
                "program_name": "Name...",
                "motivation": "Quote...",
                "nutrition_targets": { "calories": 2800, "protein": 200, "carbs": 250, "fats": 70 },
                "daily_commands": ["Drink water", "Sleep"],
                "schedule": [
                    { "day": "Day 1...", "exercises": [{ "name": "...", "sets": "4", "reps": "8-10" }] }
                ]
            }
        `;

        const groq = getGroqClient(c);
        if (!groq) {
            return c.json({ result: "Demo Mode (API Key Missing)" });
        }

        const chatCompletion = await groq.chat.completions.create({
            messages: [{ role: "system", content: prompt }],
            model: "llama-3.1-8b-instant",
            temperature: 0.3,
            max_tokens: 1024
        });

        let jsonResponse;
        const aiResponseContent = chatCompletion.choices[0]?.message?.content || "{}";
        try {
            const cleanJson = aiResponseContent.replace(/```json/g, "").replace(/```/g, "").trim();
            jsonResponse = JSON.parse(cleanJson);
        } catch (e) {
            jsonResponse = {};
        }

        const updatedUser = await User.findOneAndUpdate(
            { email },
            { program: jsonResponse },
            { new: true }
        );
        return c.json({ result: jsonResponse, user: updatedUser });

    } catch (error) {
        return c.json({ message: "Program oluşturulamadı" }, 500);
    }
});

app.get('/get-program/:email', async (c) => {
    const email = c.req.param('email');
    const user = await User.findOne({ email });
    if (user && user.program) {
        return c.json(user.program);
    } else {
        return c.json({ message: "Program bulunamadı." }, 404);
    }
});

// Save AI Program
app.post('/save-program', async (c) => {
    try {
        const { email, program } = await c.req.json();
        if (!email || !program) {
            return c.json({ message: "Email ve program gereklidir." }, 400);
        }

        const user = await User.findOne({ email });
        if (!user) {
            return c.json({ message: "Kullanıcı bulunamadı." }, 404);
        }

        user.program = program;
        user.markModified('program'); // Critical for Mixed type
        await user.save();

        return c.json({ message: "Program başarıyla kaydedildi.", program: user.program });
    } catch (error) {
        console.error("Program kayıt hatası:", error);
        return c.json({ message: "Program kaydedilirken hata oluştu.", error: error.message }, 500);
    }
});

// Add Exercise to Program
app.post('/program/add-exercise', async (c) => {
    try {
        const { email, day, exercises } = await c.req.json(); // exercises should be an array
        const user = await User.findOne({ email });

        if (!user || !user.program || !user.program.schedule) {
            return c.json({ message: "Kullanıcı veya program bulunamadı." }, 404);
        }

        // Find the specific day in the schedule
        const daySchedule = user.program.schedule.find(s => s.day === day);
        if (!daySchedule) {
            return c.json({ message: "Programda bu gün bulunamadı." }, 404);
        }

        // Ensure exercises array exists
        if (!daySchedule.exercises) daySchedule.exercises = [];

        // Normalize input to array
        const exercisesToAdd = Array.isArray(exercises) ? exercises : [exercises];
        const enrichedExercises = [];

        for (const ex of exercisesToAdd) {
            // Try to find exercise in DB by name or ID
            let dbExercise = null;
            if (ex._id) {
                dbExercise = await Exercise.findById(ex._id);
            } else if (ex.name) {
                dbExercise = await Exercise.findOne({ name: ex.name });
            }

            if (dbExercise) {
                // Merge DB details with user input (user input overrides conflicting fields like sets/reps if needed)
                enrichedExercises.push({
                    name: dbExercise.name,
                    muscleGroup: dbExercise.muscleGroup,
                    videoUrl: dbExercise.videoUrl,
                    imageUrl: dbExercise.imageUrl,
                    difficulty: dbExercise.difficulty,
                    description: dbExercise.description,
                    sets: ex.sets || "4", // Default or user provided
                    reps: ex.reps || "10", // Default or user provided
                    note: ex.note
                });
            } else {
                // If not found in DB, just add what the user sent
                enrichedExercises.push(ex);
            }
        }

        // Add the enriched exercises
        daySchedule.exercises.push(...enrichedExercises);

        // Mark 'program' as modified since it's a Mixed type
        user.markModified('program');
        await user.save();

        return c.json({ message: "Egzersizler programa eklendi.", program: user.program });

    } catch (error) {
        console.error("Program update error:", error);
        return c.json({ message: "Egzersiz eklenirken hata oluştu.", error: error.message }, 500);
    }
});

// Chat AI & TTS
app.post('/chat-ai', async (c) => {
    try {
        const { message, email } = await c.req.json();
        let history = [];
        if (email) {
            const user = await User.findOne({ email });
            if (user && user.chatHistory) {
                history = user.chatHistory.slice(-10).map(h => ({ role: h.role, content: h.content }));
            }
        }

        const systemPrompt = `You are "Coach", an energetic and friendly sports trainer.
    
    Your Task:
    Answer the user's questions about fitness, nutrition, and health.
    
    Communication Rules (STRICTLY FOLLOW THESE):
    1. NEVER talk like "Wikipedia". Avoid formality. You hate robotic language.
    2. KEEP ANSWERS SHORT. Max 2-3 sentences with a punchy delivery. Don't write an essay.
    3. No cliché intros like "Hello, how can I help you?". Get straight to the point.
    4. Use friendly nicknames (Champ, buddy, machine, king, bro).
    5. Don't drown the user in scientific jargon. Instead of saying "sarcoplasmic hypertrophy", say "if you want big muscles, you gotta lift heavy".
    6. Be motivating but realistic. Accept no excuses.
    7. Use emojis but don't overdo it (💪, 🔥, 🥗).
    8. IMPORTANT: ALWAYS ANSWER IN ENGLISH.
    `;

        const groq = getGroqClient(c);
        if (!groq) return c.json({ reply: "Service Unavailable" });

        const chatCompletion = await groq.chat.completions.create({
            messages: [
                { role: "system", content: systemPrompt },
                ...history,
                { role: "user", content: message }
            ],
            model: "llama-3.1-8b-instant",
            temperature: 0.7,
            max_tokens: 150,
        });

        const reply = chatCompletion.choices[0]?.message?.content || "Anlaşılamadı.";

        if (email) {
            await User.findOneAndUpdate(
                { email },
                {
                    $push: {
                        chatHistory: {
                            $each: [
                                { role: 'user', content: message },
                                { role: 'assistant', content: reply }
                            ]
                        }
                    }
                }
            );
        }

        // TTS Logic - Using Cloudflare R2
        let audioUrl = null;
        try {
            const R2_BUCKET_NAME = getEnv(c, 'R2_BUCKET_NAME');
            if (!R2_BUCKET_NAME) {
                throw new Error("R2 not configured");
            }

            const audioResponse = await groq.audio.speech.create({
                model: "canopylabs/orpheus-v1-english",
                voice: "daniel",
                input: reply,
                response_format: "wav"
            });

            const buffer = Buffer.from(await audioResponse.arrayBuffer());
            const fileName = `audio/speech-${Date.now()}-${Math.floor(Math.random() * 1000)}.wav`;

            audioUrl = await uploadToR2(c, buffer, fileName, 'audio/wav');

        } catch (e) {
            console.warn("TTS or R2 failed:", e.message);
            // Fallback: don't return audio if validation fails
        }

        return c.json({
            reply: reply,
            audioUrl: audioUrl
        });

    } catch (error) {
        console.error("Chat Error:", error);
        return c.json({ reply: "Hata oluştu." }, 500);
    }
});

// --- EXERCISE DATABASE ENDPOINTS ---

// Seed Exercises
app.post('/exercises/seed', async (c) => {
    try {
        const initialExercises = [
            {
                name: "Bench Press",
                description: "A compound exercise that targets the chest, shoulders, and triceps.",
                muscleGroup: "Chest",
                difficulty: "Intermediate",
                videoUrl: "https://www.youtube.com/watch?v=rT7DgCr-3pg",
                imageUrl: "https://example.com/bench-press.jpg"
            },
            {
                name: "Squat",
                description: "A compound exercise that targets the quadriceps, hamstrings, and glutes.",
                muscleGroup: "Legs",
                difficulty: "Intermediate",
                videoUrl: "https://www.youtube.com/watch?v=UltWZb7R46c",
                imageUrl: "https://example.com/squat.jpg"
            },
            {
                name: "Deadlift",
                description: "A compound exercise that targets the entire posterior chain.",
                muscleGroup: "Back",
                difficulty: "Advanced",
                videoUrl: "https://www.youtube.com/watch?v=op9kVnSso6Q",
                imageUrl: "https://example.com/deadlift.jpg"
            },
            {
                name: "Pull-Up",
                description: "An upper-body compound exercise.",
                muscleGroup: "Back",
                difficulty: "Intermediate",
                videoUrl: "https://www.youtube.com/watch?v=eGo4IYlbE5g",
                imageUrl: "https://example.com/pullup.jpg"
            },
            {
                name: "Dumbbell Shoulder Press",
                description: "An exercise for shoulder strength and stability.",
                muscleGroup: "Shoulders",
                difficulty: "Beginner",
                videoUrl: "https://www.youtube.com/watch?v=qEwKCR5JCog",
                imageUrl: "https://example.com/shoulder-press.jpg"
            }
        ];

        let addedCount = 0;
        for (const ex of initialExercises) {
            const exists = await Exercise.findOne({ name: ex.name });
            if (!exists) {
                await new Exercise(ex).save();
                addedCount++;
            }
        }

        return c.json({ message: `${addedCount} exercises added to the database.`, success: true });
    } catch (error) {
        return c.json({ message: "Seed failed", error: error.message }, 500);
    }
});

// Get All Exercises
app.get('/exercises', async (c) => {
    try {
        const exercises = await Exercise.find();
        return c.json(exercises);
    } catch (error) {
        return c.json({ message: "Failed to fetch exercises", error: error.message }, 500);
    }
});

// Create Exercise
app.post('/exercises', async (c) => {
    try {
        const body = await c.req.json();
        const newExercise = new Exercise(body);
        await newExercise.save();
        return c.json(newExercise, 201);
    } catch (error) {
        return c.json({ message: "Failed to create exercise", error: error.message }, 500);
    }
});

// Get Single Exercise
app.get('/exercises/:id', async (c) => {
    try {
        const id = c.req.param('id');
        const exercise = await Exercise.findById(id);
        if (!exercise) return c.json({ message: "Exercise not found" }, 404);
        return c.json(exercise);
    } catch (error) {
        return c.json({ message: "Error fetching exercise", error: error.message }, 500);
    }
});

// MIGRATION ENDPOINT
app.post('/migrate-notes-to-sets', async (c) => {
    try {
        const users = await User.find({});
        let migratedCount = 0;

        for (const user of users) {
            let userModified = false;
            if (user.workoutLogs && user.workoutLogs.length > 0) {
                for (const log of user.workoutLogs) {
                    // Only migrate if we have a note and sets are empty/non-existent
                    if (log.note && (!log.sets || log.sets.length === 0)) {
                        try {
                            // Expected format: "4 set, 12/12/12/12 tekrar, 20/20/20/20kg"
                            const parts = log.note.split(',').map(p => p.trim());
                            if (parts.length >= 3) {
                                // Extract Reps
                                const repsPart = parts[1].replace(' tekrar', ''); // "12/12/12/12"
                                const repsArray = repsPart.split('/').map(Number); // [12, 12, 12, 12]

                                // Extract Weights
                                const weightPart = parts[2].replace('kg', ''); // "20/20/20/20"
                                const weightArray = weightPart.split('/').map(Number); // [20, 20, 20, 20]

                                const newSets = [];
                                for (let i = 0; i < repsArray.length; i++) {
                                    newSets.push({
                                        reps: repsArray[i] || 0,
                                        weight: weightArray[i] || 0,
                                        rpe: 0 // Default RPE
                                    });
                                }

                                if (newSets.length > 0) {
                                    log.sets = newSets;
                                    log.note = undefined; // Remove the note
                                    userModified = true;
                                }
                            }
                        } catch (e) {
                            console.error(`Error parsing log for user ${user.email}:`, e);
                            // Continue to next log
                        }
                    }
                }
            }

            if (userModified) {
                await user.save();
                migratedCount++;
            }
        }

        return c.json({ message: `Migration complete. Updated ${migratedCount} users.` });
    } catch (error) {
        console.error("Migration error:", error);
        return c.json({ message: "Migration failed", error: error.message }, 500);
    }
});

export default app
