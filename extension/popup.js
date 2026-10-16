/**
 * URL Guard - Extension Popup Controller
 * 
 * Directly connects to the backend trained Random Forest ML model (/api/analyze)
 * and synchronizes with the background service worker.
 * 
 * Eliminates duplicate heuristic fallbacks and prevents false Safe verdicts
 * by cleanly displaying "Analysis Unavailable" when the backend or model is offline.
 */

const DEFAULT_API_BASE_URL = 'http://localhost:3000';
const LOW_THRESH = 0.38;
const HIGH_THRESH = 0.81;

// Multilingual translations for popup explanation
const EXPLAINER_TRANSLATIONS = {
  en: {
    safe_title: 'Safe Web Address',
    safe_msg: 'This link looks normal. Remember never to share your bank PIN or OTP on unfamiliar pages.',
    safe_action: 'You can browse this website. Maintain normal security hygiene.',
    suspicious_title: 'Warning: Suspicious Link',
    suspicious_msg: 'This link looks unusual and may lead to a fake website. Do not enter passwords, OTPs, or banking details.',
    suspicious_action: 'Do not enter passwords or OTPs here. Open the official website directly if you need to check your account.',
    malicious_title: 'Danger: Malicious Web Address',
    malicious_msg: 'This link is dangerous and likely created to steal your money or passwords. Close this page immediately!',
    malicious_action: 'Do not click or enter anything. Close this window immediately and do not download any files.',
    unavailable_title: 'Security Analysis Unavailable',
    unavailable_msg: 'URL Guard could not connect to the backend ML analysis server. The safety of this web address cannot be verified.',
    unavailable_action: 'Do not assume this website is safe. Ensure the URL Guard backend server is running.'
  },
  ta: {
    safe_title: 'பாதுகாப்பான இணையதளம்',
    safe_msg: 'இந்த லிங்க் சாதாரணமாகத் தெரிகிறது. உங்கள் password அல்லது OTP-ஐ தேவையின்றி எங்கும் கொடுக்காதீர்கள்.',
    safe_action: 'இந்தப் பக்கத்தை நீங்கள் திறக்கலாம். ஆனாலும் எந்த மென்பொருளும் 100% உத்தரவாதம் அளிக்க முடியாது என்பதால் விழிப்புடன் இருக்கவும்.',
    suspicious_title: 'எச்சரிக்கை: சந்தேகத்திற்குரிய இணைப்பு',
    suspicious_msg: 'இந்த லிங்க் சந்தேகமாக இருக்கிறது. இது போலியான இணையதளமாக இருக்கலாம். உங்கள் password அல்லது OTP-ஐ இதில் கொடுக்காதீர்கள்.',
    suspicious_action: 'இந்த பக்கத்தில் உங்கள் Password, OTP, வங்கி விவரங்களை ஒருபோதும் உள்ளிடாதீர்கள். அதிகாரப்பூர்வ தளத்தை நேரடியாகத் திறக்கவும்.',
    malicious_title: 'ஆபத்து: தீங்கிழைக்கும் தளம்',
    malicious_msg: 'இந்த லிங்க் மிகவும் ஆபத்தானது. உங்கள் பணத்தையோ அல்லது தனிப்பட்ட தகவல்களையோ திருட இது உருவாக்கப்பட்டிருக்கலாம்.',
    malicious_action: 'இந்த லிங்கைத் திறக்காதீர்கள். உடனே இந்தப் பக்கத்தை மூடிவிடுங்கள். எதையும் டவுன்லோட் செய்யாதீர்கள்.',
    unavailable_title: 'பகுப்பாய்வு கிடைக்கவில்லை',
    unavailable_msg: 'URL Guard ML சர்வரைத் தொடர்பு கொள்ள முடியவில்லை. இந்த இணைப்பின் பாதுகாப்பை உறுதிப்படுத்த இயலவில்லை.',
    unavailable_action: 'இந்த தளம் பாதுகாப்பானது என்று கருதாதீர்கள். சர்வர் இயங்குகிறதா என்பதை உறுதிப்படுத்தவும்.'
  },
  hi: {
    safe_title: 'सुरक्षित वेब लिंक',
    safe_msg: 'यह लिंक सामान्य दिखता है। कोई हानिकारक लक्षण नहीं मिले। फिर भी अपना पासवर्ड या बैंक ओटीपी किसी अनजान पेज पर कभी न डालें।',
    safe_action: 'आप इस वेबसाइट पर जा सकते हैं। कोई भी स्वचालित प्रणाली 100% गारंटी नहीं दे सकती, सतर्क रहें।',
    suspicious_title: 'चेतावनी: संदिग्ध लिंक',
    suspicious_msg: 'यह लिंक असामान्य लग रहा है और यह नकली वेबसाइट हो सकती है। इसमें अपना पासवर्ड या ओटीपी न डालें।',
    suspicious_action: 'इस पेज पर अपना पासवर्ड, बैंक खाता या ओटीपी बिल्कुल न भरें। आधिकारिक वेबसाइट सीधे खोलें।',
    malicious_title: 'खतरा: दुर्भावनापूर्ण (Malicious) लिंक',
    malicious_msg: 'यह लिंक बेहद खतरनाक है और इसे आपकी निजी जानकारी या पैसे चुराने के लिए बनाया गया है।',
    malicious_action: 'इस लिंक को तुरंत बंद कर दें। कोई भी फाइल डाउनलोड न करें और कोई पासवर्ड न डालें।',
    unavailable_title: 'सुरक्षा विश्लेषण अनुपलब्ध',
    unavailable_msg: 'URL Guard बैकएंड ML सर्वर से संपर्क नहीं हो पाया। इस लिंक की सुरक्षा सत्यापित नहीं की जा सकती।',
    unavailable_action: 'इस वेबसाइट को सुरक्षित न मानें। कृपया URL Guard सर्वर चालू होने की पुष्टि करें।'
  },
  te: {
    safe_title: 'సురక్షితమైన వెబ్ చిరునామా',
    safe_msg: 'ఈ లింక్ సాధారణంగా కనిపిస్తోంది. అయినప్పటికీ మీ పాస్‌వర్డ్ లేదా OTP ని ఎవరికీ ఇవ్వకండి.',
    safe_action: 'మీరు ఈ పేజీని తెరవవచ్చు. ఎల్లప్పుడూ సాధారణ భద్రతా జాగ్రత్తలు పాటించండి.',
    suspicious_title: 'హెచ్చరిక: అనుమానాస్పద లింక్',
    suspicious_msg: 'ఈ లింక్ అనుమానాస్పదంగా ఉంది మరియు నకిలీ వెబ్‌సైట్ కావచ్చు. మీ పాస్‌వర్డ్ లేదా OTP ని ఇందులో నమోదు చేయవద్దు.',
    suspicious_action: 'ఈ పేజీలో మీ పాస్‌వర్డ్, బ్యాంక్ వివరాలు లేదా OTP ని నమోదు చేయవద్దు. అధికారిక సైట్‌ను నేరుగా తెరవండి.',
    malicious_title: 'ప్రమాదం: హానికరమైన (Malicious) వెబ్‌సైట్',
    malicious_msg: 'ఈ లింక్ చాలా ప్రమాదకరమైనది. మీ డబ్బు లేదా వివరాలను దొంగిలించడానికి ఇది సృష్టించబడింది.',
    malicious_action: 'ఈ లింక్‌ను తెరవవద్దు. వెంటనే ఈ విండోను మూసివేయండి.',
    unavailable_title: 'విశ్లేషణ అందుబాటులో లేదు',
    unavailable_msg: 'URL Guard బ్యాకెండ్ సర్వర్‌ను సంప్రదించలేకపోయింది. ఈ లింక్ భద్రతను ధృవీకరించలేము.',
    unavailable_action: 'ఈ సైట్ సురక్షితమైనదిగా భావించవద్దు. దయచేసి సర్వర్ నడుస్తోందని నిర్ధారించుకోండి.'
  },
  kn: {
    safe_title: 'ಸುರಕ್ಷಿತ ವೆಬ್ ವಿಳಾಸ',
    safe_msg: 'ಈ ಲಿಂಕ್ ಸಹಜವಾಗಿ ಕಾಣುತ್ತಿದೆ. ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ಅನ್ನು ಅಪರಿಚಿತ ಪುಟಗಳಲ್ಲಿ ನಮೂದಿಸಬೇಡಿ.',
    safe_action: 'ನೀವು ಈ ಪುಟವನ್ನು ತೆರೆಯಬಹುದು. ಜಾಗರೂಕರಾಗಿರಿ.',
    suspicious_title: 'ಎಚ್ಚರಿಕೆ: ಸಂಶಯಾಸ್ಪದ ಲಿಂಕ್',
    suspicious_msg: 'ಈ ಲಿಂಕ್ ಅಸಹಜವಾಗಿದೆ ಮತ್ತು ನಕಲಿ ವೆಬ್‌ಸೈಟ್ ಆಗಿರಬಹುದು. ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ಅನ್ನು ನಮೂದಿಸಬೇಡಿ.',
    suspicious_action: 'ಈ ಪುಟದಲ್ಲಿ ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ಅನ್ನು ನಮೂದಿಸಬೇಡಿ. ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್ ಅನ್ನು ನೇರವಾಗಿ ತೆರೆಯಿರಿ.',
    malicious_title: 'ಅಪಾಯ: ಹಾನಿಕಾರಕ ವೆಬ್‌ಸೈಟ್ (Malicious)',
    malicious_msg: 'ಈ ಲಿಂಕ್ ಅತ್ಯಂತ ಅಪಾಯಕಾರಿಯಾಗಿದೆ. ನಿಮ್ಮ ಹಣ ಅಥವಾ ವೈಯಕ್ತಿಕ ಮಾಹಿತಿಯನ್ನು ಕದಿಯಲು ರಚಿಸಲಾಗಿದೆ.',
    malicious_action: 'ಯಾವುದೇ ವಿವರ ನೀಡಬೇಡಿ. ತಕ್ಷಣವೇ ಈ ಪುಟವನ್ನು ಮುಚ್ಚಿ.',
    unavailable_title: 'ವಿಶ್ಲೇಷಣೆ ಲಭ್ಯವಿಲ್ಲ',
    unavailable_msg: 'URL Guard ಬ್ಯಾಕೆಂಡ್ ಸರ್ವರ್ ಸಂಪರ್ಕಿಸಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ. ಈ ಲಿಂಕ್ ಸುರಕ್ಷತೆಯನ್ನು ಖಚಿತಪಡಿಸಲು ಸಾಧ್ಯವಿಲ್ಲ.',
    unavailable_action: 'ಈ ಸೈಟ್ ಸುರಕ್ಷಿತವೆಂದು ಭಾವಿಸಬೇಡಿ. ದಯವಿಟ್ಟು ಸರ್ವರ್ ಚಾಲನೆಯಲ್ಲಿದೆ ಎಂದು ಖಚಿತಪಡಿಸಿಕೊಳ್ಳಿ.'
  },
  ml: {
    safe_title: 'സുരക്ഷിതമായ വെബ് വിലാസം',
    safe_msg: 'ഈ ലിങ്ക് സാധാരണമായി കാണപ്പെടുന്നു. പാസ്‌വേഡ് അല്ലെങ്കിൽ OTP ആവശ്യമില്ലാതെ ആർക്കും നൽകരുത്.',
    safe_action: 'നിങ്ങൾക്ക് ഈ പേജ് സന്ദർശിക്കാം. ജാഗ്രത പാലിക്കുക.',
    suspicious_title: 'മുന്നറിയിപ്പ്: സംശയാസ്പദമായ ലിങ്ക്',
    suspicious_msg: 'ഈ ലിങ്ക് സംശയാസ്പദമാണ്, ഇത് വ്യാജ വെബ്‌സൈറ്റ് ആകാൻ സാധ്യതയുണ്ട്. പാസ്‌വേഡോ ഒടിപിയോ ഇതിൽ നൽകരുത്.',
    suspicious_action: 'ഈ പേജിൽ പാസ്‌വേഡോ ഒടിപിയോ നൽകരുത്. ഔദ്യോഗിക വെബ്‌സൈറ്റ് നേരിട്ട് തുറക്കുക.',
    malicious_title: 'അപകടം: ദോഷകരമായ വെബ്‌സൈറ്റ് (Malicious)',
    malicious_msg: 'ഈ ലിങ്ക് വളരെ അപകടകരമാണ്. നിങ്ങളുടെ പണമോ വിവരങ്ങളോ തട്ടിയെടുക്കാൻ നിർമ്മിച്ചതാകാം.',
    malicious_action: 'ഈ പേജ് ഉടൻ തന്നെ ക്ലോസ് ചെയ്യുക. യാതൊരു വിവരങ്ങളും നൽകരുത്.',
    unavailable_title: 'വിശകലനം ലഭ്യമല്ല',
    unavailable_msg: 'URL Guard ബാക്കെൻഡ് സെർവറുമായി ബന്ധപ്പെടാൻ കഴിഞ്ഞില്ല. സുരക്ഷ സ്ഥിരീകരിക്കാനായില്ല.',
    unavailable_action: 'ഈ വെബ്‌സൈറ്റ് സുരക്ഷിതമാണെന്ന് കരുതരുത്. ദയവായി സെർവർ പ്രവർത്തിക്കുന്നുണ്ടെന്ന് ഉറപ്പാക്കുക.'
  }
};

let currentResult = {
  url: '',
  score: null,
  verdict: 'Analysis Unavailable',
  reasons: [],
  simple_explanation: null
};

let currentLanguage = 'en';
let apiBaseUrl = DEFAULT_API_BASE_URL;

// Read API URL from storage
async function loadApiBaseUrl() {
  return new Promise((resolve) => {
    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.local) {
      chrome.storage.local.get(['url_guard_api_url'], (res) => {
        apiBaseUrl = (res && res.url_guard_api_url) ? res.url_guard_api_url.trim().replace(/\/+$/, '') : DEFAULT_API_BASE_URL;
        const input = document.getElementById('api-base-url-input');
        if (input) input.value = apiBaseUrl;
        resolve(apiBaseUrl);
      });
    } else {
      resolve(DEFAULT_API_BASE_URL);
    }
  });
}

// Set circular gauge
function setGauge(score) {
  const circle = document.getElementById('gauge-circle');
  const scoreText = document.getElementById('gauge-score');
  const radius = 34;
  const circumference = 2 * Math.PI * radius; // ~213.6

  if (typeof score !== 'number' || isNaN(score)) {
    circle.style.strokeDashoffset = circumference;
    circle.style.stroke = '#64748b'; // Gray for unavailable
    scoreText.textContent = 'N/A';
    return;
  }

  const clamped = Math.max(0, Math.min(1, score));
  const offset = circumference - (clamped * circumference);

  circle.style.strokeDashoffset = offset;
  scoreText.textContent = clamped.toFixed(2);

  if (clamped > HIGH_THRESH) {
    circle.style.stroke = '#ef4444'; // Red
  } else if (clamped >= LOW_THRESH) {
    circle.style.stroke = '#f59e0b'; // Amber
  } else {
    circle.style.stroke = '#10b981'; // Emerald
  }
}

// Render UI with synchronized classification result
function renderResult(result) {
  currentResult = result;

  const urlDisplay = document.getElementById('target-url-text');
  urlDisplay.textContent = result.url || 'No active web URL';

  setGauge(result.score);

  const badge = document.getElementById('verdict-badge');
  const subtitle = document.getElementById('verdict-subtitle');
  const actionBox = document.getElementById('action-box');

  const v = (result.verdict || '').toLowerCase();

  if (result.verdict === 'Malicious') {
    badge.className = 'verdict-badge malicious';
    badge.textContent = 'Malicious (High Risk)';
    subtitle.textContent = typeof result.score === 'number'
      ? `Score ${result.score.toFixed(4)} > 0.81 threshold`
      : 'Classified malicious by threat intelligence / ML rules';
    actionBox.className = 'action-box danger-box';
  } else if (result.verdict === 'Suspicious') {
    badge.className = 'verdict-badge suspicious';
    badge.textContent = 'Suspicious (Elevated Risk)';
    subtitle.textContent = typeof result.score === 'number'
      ? `Score ${result.score.toFixed(4)} in [0.38 - 0.81] band`
      : 'Suspicious infrastructure characteristics detected';
    actionBox.className = 'action-box warning-box';
  } else if (result.verdict === 'Safe') {
    badge.className = 'verdict-badge safe';
    badge.textContent = 'Safe (Low Risk)';
    subtitle.textContent = typeof result.score === 'number'
      ? `Score ${result.score.toFixed(4)} < 0.38 threshold`
      : 'URL matches benign patterns';
    actionBox.className = 'action-box safe-box';
  } else if (result.verdict === 'Internal') {
    badge.className = 'verdict-badge unavailable';
    badge.textContent = 'Internal Browser Page';
    subtitle.textContent = 'Local browser interface (non-HTTP)';
    actionBox.className = 'action-box unavailable-box';
  } else {
    // Analysis Unavailable
    badge.className = 'verdict-badge unavailable';
    badge.textContent = 'Analysis Unavailable';
    subtitle.textContent = result.error || 'Backend ML server offline or unreachable';
    actionBox.className = 'action-box unavailable-box';
  }

  updateExplainerText();

  // Indicators list
  const listContainer = document.getElementById('indicators-list');
  listContainer.innerHTML = '';
  
  let reasons = result.reasons;
  if (!reasons || reasons.length === 0) {
    if (result.verdict === 'Safe') {
      reasons = ['No threat indicators detected by trained ML model'];
    } else if (result.verdict === 'Analysis Unavailable') {
      reasons = ['Backend server offline', 'ML model unreachable'];
    } else {
      reasons = ['Unclassified'];
    }
  }

  for (const r of reasons) {
    const span = document.createElement('span');
    span.className = 'indicator-tag';
    span.textContent = r;
    listContainer.appendChild(span);
  }
}

// Update explanatory guidance
function updateExplainerText() {
  const trans = EXPLAINER_TRANSLATIONS[currentLanguage] || EXPLAINER_TRANSLATIONS.en;
  const titleEl = document.getElementById('explainer-title-text');
  const msgEl = document.getElementById('explainer-message-text');
  const actEl = document.getElementById('explainer-action-text');

  // If server provided a localized simple_explanation for the current language, prioritize it
  if (currentResult.simple_explanation && currentResult.simple_explanation.language === currentLanguage) {
    const exp = currentResult.simple_explanation;
    titleEl.textContent = exp.title || trans.safe_title;
    msgEl.textContent = exp.summary || trans.safe_msg;
    actEl.textContent = exp.what_to_do || trans.safe_action;
    return;
  }

  const v = (currentResult.verdict || '').toLowerCase();

  if (v === 'malicious') {
    titleEl.textContent = trans.malicious_title;
    msgEl.textContent = trans.malicious_msg;
    actEl.textContent = trans.malicious_action;
  } else if (v === 'suspicious') {
    titleEl.textContent = trans.suspicious_title;
    msgEl.textContent = trans.suspicious_msg;
    actEl.textContent = trans.suspicious_action;
  } else if (v === 'safe') {
    titleEl.textContent = trans.safe_title;
    msgEl.textContent = trans.safe_msg;
    actEl.textContent = trans.safe_action;
  } else {
    // Unavailable or internal
    titleEl.textContent = trans.unavailable_title;
    msgEl.textContent = trans.unavailable_msg;
    actEl.textContent = trans.unavailable_action;
  }
}

// If language changed, optionally fetch translated explanation from /api/explain if available
async function requestLanguageExplanation(lang) {
  if (currentResult.verdict === 'Analysis Unavailable' || currentResult.verdict === 'Internal') {
    updateExplainerText();
    return;
  }

  try {
    const res = await fetch(`${apiBaseUrl}/api/explain`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        verdict: currentResult.verdict,
        score: currentResult.score,
        ruleFlags: currentResult.evidence?.rules || [],
        topFactors: currentResult.evidence?.model_factors || [],
        intelResult: currentResult.evidence?.threat_intel || {},
        language: lang,
        url: currentResult.url
      })
    });
    if (res.ok) {
      const data = await res.json();
      if (data.simple_explanation) {
        currentResult.simple_explanation = data.simple_explanation;
      }
    }
  } catch (_) {
    // If /api/explain fails, the deterministic fallback in updateExplainerText will render
  }
  updateExplainerText();
}

/**
 * Inspect a URL via the backend ML model endpoint (/api/analyze)
 */
async function inspectUrl(rawUrl) {
  if (!rawUrl || (!rawUrl.startsWith('http://') && !rawUrl.startsWith('https://'))) {
    renderResult({
      url: rawUrl || 'about:blank',
      score: null,
      verdict: 'Internal',
      reasons: ['Internal or non-HTTP browser page']
    });
    return;
  }

  // Ask background service worker first to maintain tab synchronization
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({
      action: 'ANALYZE_URL',
      url: rawUrl,
      language: currentLanguage
    }, (response) => {
      if (chrome.runtime.lastError || !response || !response.result) {
        // Fallback to direct backend call if background didn't respond
        directBackendInspect(rawUrl);
      } else {
        renderResult(response.result);
      }
    });
  } else {
    directBackendInspect(rawUrl);
  }
}

/**
 * Direct call to /api/analyze with safe timeout and error handling
 */
async function directBackendInspect(rawUrl) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 4000);

  try {
    const res = await fetch(`${apiBaseUrl}/api/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url: rawUrl, language: currentLanguage }),
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    if (res.ok) {
      const data = await res.json();
      const reasons = [];
      if (data.evidence && Array.isArray(data.evidence.rules)) {
        for (const r of data.evidence.rules) reasons.push(r.name || r.id);
      }
      if (data.evidence && Array.isArray(data.evidence.model_factors)) {
        for (const f of data.evidence.model_factors) {
          if (f.attribution > 0.015 && reasons.length < 5) {
            reasons.push(f.human_name || f.feature_name);
          }
        }
      }

      renderResult({
        url: data.normalized_url || rawUrl,
        score: typeof data.model?.score === 'number' ? data.model.score : null,
        verdict: data.verdict,
        verdict_basis: data.verdict_basis,
        confidence_band: data.confidence_band,
        reasons: reasons.length > 0 ? reasons : ['No threat indicators detected by trained ML model'],
        simple_explanation: data.simple_explanation,
        evidence: data.evidence
      });
      return;
    }

    let errObj = {};
    try { errObj = await res.json(); } catch (_) {}
    renderResult({
      url: rawUrl,
      score: null,
      verdict: 'Analysis Unavailable',
      error: errObj.message || `Backend returned status ${res.status}`,
      reasons: [errObj.error === 'MODEL_UNAVAILABLE' ? 'Trained ML model unavailable' : 'Analysis Unavailable']
    });
  } catch (err) {
    clearTimeout(timeoutId);
    renderResult({
      url: rawUrl,
      score: null,
      verdict: 'Analysis Unavailable',
      error: 'Cannot connect to backend ML server',
      reasons: ['Backend analysis server or trained ML model unreachable']
    });
  }
}

// Initialize on DOM load
document.addEventListener('DOMContentLoaded', async () => {
  await loadApiBaseUrl();

  // Query active tab and request analysis
  if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.query) {
    chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
      if (tabs && tabs[0] && tabs[0].url) {
        const activeTab = tabs[0];
        // Request cached or fresh analysis from background worker
        chrome.runtime.sendMessage({
          action: 'GET_TAB_ANALYSIS',
          tabId: activeTab.id,
          url: activeTab.url,
          language: currentLanguage
        }, (response) => {
          if (response && response.success && response.result) {
            renderResult(response.result);
          } else {
            inspectUrl(activeTab.url);
          }
        });
      } else {
        inspectUrl('https://example.com');
      }
    });
  } else {
    inspectUrl('https://example.com');
  }

  // Language selector
  const langSelect = document.getElementById('ext-lang-select');
  if (langSelect) {
    langSelect.addEventListener('change', (e) => {
      currentLanguage = e.target.value;
      requestLanguageExplanation(currentLanguage);
    });
  }

  // Manual URL scan form
  const form = document.getElementById('quick-scan-form');
  if (form) {
    form.addEventListener('submit', (e) => {
      e.preventDefault();
      const input = document.getElementById('manual-url-input');
      const val = input.value.trim();
      if (val) {
        inspectUrl(val);
      }
    });
  }

  // Open web dashboard button
  const dashBtn = document.getElementById('open-dashboard-btn');
  if (dashBtn) {
    dashBtn.addEventListener('click', () => {
      const url = apiBaseUrl || DEFAULT_API_BASE_URL;
      if (typeof chrome !== 'undefined' && chrome.tabs && chrome.tabs.create) {
        chrome.tabs.create({ url });
      } else {
        window.open(url, '_blank');
      }
    });
  }

  // Settings toggle & configuration
  const toggleBtn = document.getElementById('toggle-settings-btn');
  const settingsPanel = document.getElementById('settings-panel');
  const saveBtn = document.getElementById('save-api-btn');
  const testBtn = document.getElementById('test-api-btn');
  const apiInput = document.getElementById('api-base-url-input');
  const statusMsg = document.getElementById('settings-status-msg');
  const connIndicator = document.getElementById('settings-conn-indicator');

  if (toggleBtn && settingsPanel) {
    toggleBtn.addEventListener('click', () => {
      settingsPanel.classList.toggle('hidden');
    });
  }

  if (saveBtn && apiInput) {
    saveBtn.addEventListener('click', () => {
      const newVal = apiInput.value.trim().replace(/\/+$/, '') || DEFAULT_API_BASE_URL;
      apiBaseUrl = newVal;
      if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
        chrome.runtime.sendMessage({ action: 'SET_API_CONFIG', apiUrl: newVal }, () => {
          statusMsg.textContent = `Saved: ${newVal}`;
          statusMsg.style.color = '#38bdf8';
        });
      } else {
        statusMsg.textContent = `Saved: ${newVal}`;
      }
    });
  }

  if (testBtn && apiInput) {
    testBtn.addEventListener('click', async () => {
      const testUrl = apiInput.value.trim().replace(/\/+$/, '') || DEFAULT_API_BASE_URL;
      statusMsg.textContent = 'Testing connection...';
      statusMsg.style.color = '#94a3b8';
      try {
        const res = await fetch(`${testUrl}/api/health`);
        if (res.ok) {
          const data = await res.json();
          if (data.model_loaded) {
            statusMsg.textContent = `Connected! Model loaded (${data.feature_count} features)`;
            statusMsg.style.color = '#34d399';
            if (connIndicator) connIndicator.textContent = 'Online';
          } else {
            statusMsg.textContent = 'Server healthy, but ML model not loaded';
            statusMsg.style.color = '#fbbf24';
          }
        } else {
          statusMsg.textContent = `Server error HTTP ${res.status}`;
          statusMsg.style.color = '#f87171';
        }
      } catch (err) {
        statusMsg.textContent = 'Cannot connect to URL Guard backend';
        statusMsg.style.color = '#f87171';
        if (connIndicator) connIndicator.textContent = 'Offline';
      }
    });
  }
});
