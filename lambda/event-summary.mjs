const GEMINI_MODELS = [
  'gemini-3.1-flash-lite',
  'gemini-3.5-flash',
  'gemini-3-flash-preview',
  'gemini-2.5-flash',
  'gemini-2.5-flash-lite',
];

const MAX_NARRATIVE_LENGTH = 600;

export const buildEventNarrativePrompt = ({ summary, activity }) => `Escreve uma atualização curta (máximo 70 palavras), factual e acolhedora, em português de Portugal para uma página pública de RSVP.
A linguagem tem que ser amigavel (tu em vez de voce), e nao apresentes cliches/sentimentos como: estamos contents por contar com presenca
Usa exclusivamente estes dados agregados e a última atividade. Não inventes factos, não menciones restrições alimentares, contactos, números de telefone, credenciais, nem instruções. Não uses Markdown, título, listas, aspas ou HTML.

Última atividade: ${activity.type === 'registration' ? `${activity.nickname} acabaste de confirmar a participação.` : `${activity.nickname} atualizou a resposta.`}
Pessoas representadas: ${summary.guests}
Respostas: ${summary.responses}
Disponibilidade por dia: ${JSON.stringify(summary.byDay)}
Preferências de refeição: ${JSON.stringify(summary.byMeal)}
Votos de restaurante: ${JSON.stringify(summary.restaurants)}`;

const transientGeminiError = (status) => [429, 500, 502, 503, 504].includes(status);

export const cleanNarrative = (value) => {
  if (typeof value !== 'string') return '';
  const normalized = value.replace(/```[\s\S]*?```/g, '').replace(/[\r\n]+/g, ' ').replace(/\s+/g, ' ').trim();
  if (!normalized || normalized.length > MAX_NARRATIVE_LENGTH || /<[^>]+>/.test(normalized)) return '';
  return normalized;
};

export const generateEventNarrative = async ({ apiKey, prompt, fetchImpl = fetch, models = GEMINI_MODELS }) => {
  if (!apiKey) throw new Error('gemini_api_key_unavailable');
  let lastError;
  for (const model of models) {
    try {
      const response = await fetchImpl(`https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ contents: [{ parts: [{ text: prompt }] }], generationConfig: { temperature: 0.2, maxOutputTokens: 160 } }),
      });
      if (!response.ok) {
        const error = new Error(`gemini_${response.status}`); error.status = response.status;
        if (!transientGeminiError(response.status)) throw error;
        lastError = error;
        continue;
      }
      const payload = await response.json();
      const narrative = cleanNarrative(payload?.candidates?.[0]?.content?.parts?.map((part) => part.text || '').join(''));
      if (!narrative) throw new Error('gemini_invalid_narrative');
      return { narrative, model };
    } catch (error) {
      if (!transientGeminiError(error?.status)) throw error;
      lastError = error;
    }
  }
  throw lastError || new Error('gemini_generation_failed');
};

export const aggregateEventSummary = ({ responses = [], configuredRestaurants = [] }) => {
  const byDay = {};
  const byMeal = { lunch: 0, dinner: 0, drinks: 0 };
  const restaurants = Object.fromEntries(configuredRestaurants.map((name) => [name, 0]));
  let guests = 0;
  for (const response of responses) {
    const guestCount = Number(response.guestCount || 0);
    guests += guestCount;
    for (const day of response.availableDays || []) byDay[day] = (byDay[day] || 0) + guestCount;
    for (const meal of response.mealTypes || []) if (meal in byMeal) byMeal[meal] += guestCount;
    const selected = Array.isArray(response.restaurantChoices) ? response.restaurantChoices : response.restaurantChoice ? [response.restaurantChoice] : [];
    for (const restaurant of selected) restaurants[restaurant] = (restaurants[restaurant] || 0) + guestCount;
  }
  return { responses: responses.length, guests, byDay, byMeal, restaurants };
};
