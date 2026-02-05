// server/index.js
import { serve } from '@hono/node-server'
import { Hono } from 'hono'
import { cors } from 'hono/cors'
import mongoose from 'mongoose'
import Groq from 'groq-sdk'
import dotenv from 'dotenv'
import { S3Client, PutObjectCommand } from '@aws-sdk/client-s3'
import { v4 as uuidv4 } from 'uuid'

dotenv.config()

const app = new Hono()

// Middleware
app.use('/*', cors())

// --- R2 STORAGE SETUP ---
const r2 = new S3Client({
  region: 'auto',
  endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
  credentials: {
    accessKeyId: process.env.R2_ACCESS_KEY_ID || '',
    secretAccessKey: process.env.R2_SECRET_ACCESS_KEY || '',
  },
})

const R2_BUCKET_NAME = process.env.R2_BUCKET_NAME
const R2_PUBLIC_URL = process.env.R2_PUBLIC_URL

async function uploadToR2(buffer, key, contentType) {
  if (!R2_BUCKET_NAME) {
    throw new Error('R2_BUCKET_NAME environment variable is not defined.')
  }

  const command = new PutObjectCommand({
    Bucket: R2_BUCKET_NAME,
    Key: key,
    Body: buffer,
    ContentType: contentType,
  })

  try {
    await r2.send(command)
    // Return Public URL
    // Ensure R2_PUBLIC_URL does not have trailing slash, and key does not have leading slash conflict
    const baseUrl = R2_PUBLIC_URL.replace(/\/$/, '')
    const cleanKey = key.replace(/^\//, '')
    return `${baseUrl}/${cleanKey}`
  } catch (error) {
    console.error('R2 Upload Error:', error)
    throw error
  }
}

// --- MONGODB CONNECTION ---
const CONNECTION_URL = "mongodb+srv://akifkarabay_db_user:OSkQckeN3LzJAMWS@cluster0.eue0vpe.mongodb.net/?appName=Cluster0";

// Ensure connection is established
mongoose.connect(CONNECTION_URL)
  .then(() => console.log("MongoDB veritabanına bağlandı!"))
  .catch((err) => console.error("Bağlantı hatası:", err));

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
  program: { type: Object },
  workoutLogs: [{
    date: { type: Date, default: Date.now },
    day: String,
    exercise: String,
    note: String
  }],
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

const User = mongoose.models.User || mongoose.model('User', UserSchema);

// --- GROQ SETUP ---
let groq;
if (process.env.GROQ_API_KEY) {
  groq = new Groq({
    apiKey: process.env.GROQ_API_KEY
  });
} else {
  console.warn("UYARI: GROQ_API_KEY bulunamadı. Yapay zeka özellikleri çalışmayacak.");
}

// --- LOGGING MIDDLEWARE ---
app.use('*', async (c, next) => {
  console.log(`[${c.req.method}] ${c.req.url}`);
  await next();
});

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
    const body = await c.req.parseBody();
    const imageFile = body['image'];

    if (!imageFile) {
      return c.json({ message: "Görüntü verisi gelmedi." }, 400);
    }

    // Convert file to base64 for Groq Analysis (still handled in memory as it's just for analysis)
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
      model: "llama-3.2-11b-vision-preview",
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
    const { email, day, exercise, note } = await c.req.json();
    const updatedUser = await User.findOneAndUpdate(
      { email: email },
      {
        $push: {
          workoutLogs: {
            day: day,
            exercise: exercise,
            note: note,
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
    const updatedUser = await User.findOneAndUpdate(
      { email: email },
      { water: waterAmount },
      { new: true }
    );
    return c.json({ message: "Su güncellendi", water: updatedUser.water });
  } catch (error) {
    return c.json({ message: "Hata oluştu" }, 500);
  }
});

// Get Water
app.get('/get-water/:email', async (c) => {
  try {
    const email = c.req.param('email');
    const user = await User.findOne({ email });
    if (user) {
      return c.json({ water: user.water });
    } else {
      return c.json({ water: 0 });
    }
  } catch (error) {
    return c.json({ message: "Hata oluştu" }, 500);
  }
});

// Google Fit Integration
async function getGoogleFitData() {
  try {
    const GOOGLE_CLIENT_ID = process.env.GOOGLE_CLIENT_ID;
    const GOOGLE_CLIENT_SECRET = process.env.GOOGLE_CLIENT_SECRET;
    const GOOGLE_REFRESH_TOKEN = process.env.GOOGLE_REFRESH_TOKEN;

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

    const tokenData = await tokenResponse.json();
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

    const fitData = await datasetResponse.json();
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
    const { email } = await c.req.json();
    const fitnessData = await getGoogleFitData();

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

        const publicUrl = await uploadToR2(buffer, fileName, mimeType);
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

    if (!groq) {
      return c.json({ result: "Demo Mode" });
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
      if (!process.env.R2_BUCKET_NAME) {
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

      audioUrl = await uploadToR2(buffer, fileName, 'audio/wav');

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


const port = 5001
console.log(`Server is running on port ${port}`)

serve({
  fetch: app.fetch,
  port
})

export default app