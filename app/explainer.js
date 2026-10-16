/**
 * NLP-Based Simple Warning Explainer for Elderly and Non-Technical Users.
 * 
 * Translates technical ML detection results and heuristic indicators into calm,
 * clear, jargon-free explanations in 6 major languages:
 *   - English (en)
 *   - Tamil / தமிழ் (ta)
 *   - Hindi / हिन्दी (hi)
 *   - Telugu / తెలుగు (te)
 *   - Kannada / ಕನ್ನಡ (kn)
 *   - Malayalam / മലയാളം (ml)
 * 
 * Core Safety Rules:
 *   1. Preserves the exact verdict produced by the detection model.
 *   2. Never invents indicators not identified by the detector.
 *   3. Never claims a URL is guaranteed safe.
 *   4. For suspicious/malicious URLs, explicitly warns against entering passwords, OTPs,
 *      ATM PINs, or banking details.
 *   5. Employs a dual-mode architecture:
 *      - Model-driven via Gemini API (gemini-3.8-flash) when GEMINI_API_KEY is present.
 *      - Pure deterministic NLP template engine as an instant, zero-dependency fallback.
 */

import { GoogleGenAI } from '@google/genai';

// Friendly indicator dictionaries across all 6 languages
const INDICATOR_DICTS = {
  en: {
    RULE_IP_HOST: 'Uses direct numbers instead of a real website name',
    RULE_USERINFO_AT: "Contains hidden '@' symbols that can trick your browser",
    RULE_PUNYCODE_IDN: 'Uses lookalike foreign letters to impersonate another website',
    RULE_BRAND_MISMATCH: 'Mentions a famous company name inside an unofficial website address',
    RULE_TYPOSQUATTING: 'Spells a trusted brand name slightly incorrectly to trick you (typosquatting)',
    RULE_EXCESSIVE_SUBDOMAINS: 'Multiple subdomains and unusually long web address',
    RULE_NESTED_URL_IN_QUERY: 'Hides a second website address inside the link (redirect trick)',
    RULE_RISKY_EXTENSION: 'Attempts to download a dangerous computer program or script file',
    RULE_SHORTENER_MASK: 'Uses a link-shortening service that hides where the link really goes',
    RULE_DOUBLE_SLASH_PATH: 'Contains unusual double slashes in the page path',
    RULE_NON_STANDARD_PORT: 'Connects through an unusual technical port',
    is_ip_host: 'Direct numeric address without a domain name',
    brand_mismatch: 'Company name does not match the actual website owner',
    risky_file_extension: 'Points directly to an executable or script file',
    is_shortener: 'Shortened link hiding the final destination',
    tld_category: 'Uses a web ending frequently associated with scam websites',
    suspicious_token_count: 'Contains sensitive keywords like login, verify, OTP, or password',
    subdomain_count: 'Multiple subdomains and complex web address structure',
    dot_count: 'Unusual number of dots in the address',
    url_length: 'Unusually long and convoluted web address'
  },
  ta: {
    RULE_IP_HOST: 'பெயருக்குப் பதிலாக வெறும் எண்களைப் பயன்படுத்துகிறது',
    RULE_USERINFO_AT: "ஏமாற்றும் வகையில் '@' குறியீட்டைக் கொண்டுள்ளது",
    RULE_PUNYCODE_IDN: 'பிரபல தளத்தைப் போலத் தோற்றமளிக்கும் போலி எழுத்துக்களைக் கொண்டுள்ளது',
    RULE_BRAND_MISMATCH: 'பிரபல நிறுவனத்தின் அல்லது வங்கியின் பெயரைப் போலியாகப் பயன்படுத்துகிறது',
    RULE_TYPOSQUATTING: 'பிரபல நிறுவனத்தின் பெயரை எழுத்துப்பிழையுடன் ஏமாற்றும் நோக்கில் பயன்படுத்துகிறது',
    RULE_EXCESSIVE_SUBDOMAINS: 'பல துணைப் பிரிவுகளைக் கொண்ட (subdomains) குழப்பமான இணைய முகவரி',
    RULE_NESTED_URL_IN_QUERY: 'உண்மையான முகவரியை மறைத்து மற்றொரு முகவரிக்குத் திசைதிருப்புகிறது',
    RULE_RISKY_EXTENSION: 'ஆபத்தான ஃபைலை டவுன்லோட் செய்ய முயற்சிக்கிறது',
    RULE_SHORTENER_MASK: 'உண்மையான இணையதள முகவரியை மறைக்கும் சுருக்கப்பட்ட லிங்க்',
    RULE_DOUBLE_SLASH_PATH: 'முகவரியில் வழக்கத்திற்கு மாறான இரட்டை சாய்வு கோடுகள் (//) உள்ளன',
    RULE_NON_STANDARD_PORT: 'வழக்கத்திற்கு மாறான தொழில்நுட்ப போர்ட் மூலம் இணைகிறது',
    is_ip_host: 'பெயருக்குப் பதிலாக வெறும் எண்கள் மட்டும் கொண்ட முகவரி',
    brand_mismatch: 'நிறுவனத்தின் பெயர் உண்மையான இணையதளத்துடன் பொருந்தவில்லை',
    risky_file_extension: 'ஆபத்தான கணினி ஃபைலைக் குறிக்கிறது',
    is_shortener: 'உண்மையான முகவரியை மறைக்கும் சுருக்கப்பட்ட இணைப்பு',
    tld_category: 'மோசடிகளுக்கு அதிகம் பயன்படுத்தப்படும் இணையதள முடிவு',
    suspicious_token_count: 'லாகின், OTP அல்லது கடவுச்சொல் போன்ற முக்கியமான வார்த்தைகளைக் கொண்டுள்ளது',
    subdomain_count: 'பல துணை முகவரிகளைக் கொண்ட வழக்கத்திற்கு மாறான அமைப்பு',
    dot_count: 'முகவரியில் வழக்கத்திற்கு அதிகமான புள்ளிகள் உள்ளன',
    url_length: 'தேவையற்ற மிக நீண்ட மற்றும் சிக்கலான இணைய முகவரி'
  },
  hi: {
    RULE_IP_HOST: 'वेबसाइट के असली नाम की जगह सीधे अंकों का उपयोग करता है',
    RULE_USERINFO_AT: "ब्राउज़र को चकमा देने के लिए '@' चिन्ह का उपयोग किया गया है",
    RULE_PUNYCODE_IDN: 'असली वेबसाइट जैसा दिखने वाले नकली अक्षरों का उपयोग करता है',
    RULE_BRAND_MISMATCH: 'किसी मशहूर बैंक या कंपनी के नाम का अनधिकृत लिंक में इस्तेमाल कर रहा है',
    RULE_TYPOSQUATTING: 'भरोसेमंद नाम की गलत स्पेलिंग लिखकर धोखा देने की कोशिश है',
    RULE_EXCESSIVE_SUBDOMAINS: 'असामान्य रूप से लंबा और कई हिस्सों वाला वेब पता',
    RULE_NESTED_URL_IN_QUERY: 'असली पते को छिपाकर किसी दूसरे पते पर भेजने की चाल',
    RULE_RISKY_EXTENSION: 'खतरनाक प्रोग्राम या वायरस फाइल डाउनलोड करवाने का प्रयास',
    RULE_SHORTENER_MASK: 'असली वेबसाइट को छिपाने वाला छोटा लिंक (Short URL)',
    RULE_DOUBLE_SLASH_PATH: 'वेब पते में असामान्य डबल स्लैश (//) मौजूद हैं',
    RULE_NON_STANDARD_PORT: 'असामान्य नेटवर्क पोर्ट से कनेक्ट हो रहा है',
    is_ip_host: 'बिना नाम वाला केवल अंकों का संख्यात्मक पता',
    brand_mismatch: 'कंपनी का नाम असली वेबसाइट के मालिक से मेल नहीं खाता',
    risky_file_extension: 'खतरनाक कंप्यूटर प्रोग्राम फाइल का लिंक',
    is_shortener: 'असली गंतव्य को छिपाने वाला छोटा लिंक',
    tld_category: 'ऑनलाइन फ्रॉड और स्कैम में बहुतायत से इस्तेमाल होने वाला डोमेन एक्सटेंशन',
    suspicious_token_count: 'लॉगिन, ओटीपी, पासवर्ड या बैंक से जुड़े संवेदनशील शब्द',
    subdomain_count: 'काफी सारे सब-डोमेन वाला जटिल पता',
    dot_count: 'पते में असामान्य रूप से ज्यादा डॉट्स (.) मौजूद हैं',
    url_length: 'अत्यधिक लंबा और संदिग्ध वेब पता'
  },
  te: {
    RULE_IP_HOST: 'అసలు వెబ్‌సైట్ పేరుకు బదులుగా కేవలం అంకెలను ఉపయోగిస్తోంది',
    RULE_USERINFO_AT: "మోసపూరిత '@' చిహ్నాన్ని కలిగి ఉంది",
    RULE_PUNYCODE_IDN: 'ప్రసిద్ధ సైట్ లాగా కనిపించే నకిలీ అక్షరాలను వాడుతోంది',
    RULE_BRAND_MISMATCH: 'ప్రముఖ బ్యాంక్ లేదా సంస్థ పేరును అనధికారిక లింక్‌లో వాడుతోంది',
    RULE_TYPOSQUATTING: 'మోసం చేయడానికి అసలు బ్రాండ్ స్పెల్లింగ్‌ను స్వల్పంగా మార్చారు',
    RULE_EXCESSIVE_SUBDOMAINS: 'అసహజమైన రీతిలో చాలా ఉప-విభాగాలు (subdomains) ఉన్న చిరునామా',
    RULE_NESTED_URL_IN_QUERY: 'నిజమైన అడ్రస్‌ను దాచి వేరే పేజీకి మళ్లించే ట్రిక్',
    RULE_RISKY_EXTENSION: 'ప్రమాదకరమైన సాఫ్ట్‌వేర్ లేదా వైరస్ ఫైల్‌ను డౌన్‌లోడ్ చేసే ప్రయత్నం',
    RULE_SHORTENER_MASK: 'అసలు వెబ్‌సైట్ ఎక్కడికో తెలియకుండా దాచే షార్ట్ లింక్',
    RULE_DOUBLE_SLASH_PATH: 'చిరునామాలో అసాధారణ డబుల్ స్లాష్‌లు (//) ఉన్నాయి',
    RULE_NON_STANDARD_PORT: 'అసాధారణ సాంకేతిక పోర్ట్ ద్వారా కనెక్ట్ అవుతోంది',
    is_ip_host: 'పేరు లేని కేవలం సంఖ్యల అడ్రస్',
    brand_mismatch: 'కంపెనీ పేరు అసలు వెబ్‌సైట్‌తో సరిపోలడం లేదు',
    risky_file_extension: 'ప్రమాదకరమైన కంప్యూటర్ ఫైల్‌కు దారితీస్తోంది',
    is_shortener: 'నిజమైన లింక్‌ను దాచే చిన్న లింక్',
    tld_category: 'స్కామ్‌లలో ఎక్కువగా ఉపయోగించే వెబ్ ముగింపు',
    suspicious_token_count: 'లాగిన్, OTP లేదా పాస్‌వర్డ్ వంటి సున్నితమైన పదాలు ఉన్నాయి',
    subdomain_count: 'చాలా సబ్‌డొమైన్‌లు కలిగిన సంక్లిష్టమైన చిరునామా',
    dot_count: 'చిరునామాలో చాలా ఎక్కువ చుక్కలు (.) ఉన్నాయి',
    url_length: 'అత్యంత పొడవైన అనుమానాస్పద వెబ్ అడ్రస్'
  },
  kn: {
    RULE_IP_HOST: 'ನಿಜವಾದ ವೆಬ್‌ಸೈಟ್ ಹೆಸರಿನ ಬದಲು ಕೇವಲ ಸಂಖ್ಯೆಗಳನ್ನು ಬಳಸುತ್ತಿದೆ',
    RULE_USERINFO_AT: "ಮೋಸಗೊಳಿಸುವ ಉದ್ದೇಶದಿಂದ '@' ಚಿಹ್ನೆಯನ್ನು ಬಳಸಲಾಗಿದೆ",
    RULE_PUNYCODE_IDN: 'ಜನಪ್ರಿಯ ತಾಣದಂತೆ ಕಾಣುವ ನಕಲಿ ಅಕ್ಷರಗಳನ್ನು ಬಳಸುತ್ತಿದೆ',
    RULE_BRAND_MISMATCH: 'ಜನಪ್ರಿಯ ಬ್ಯಾಂಕ್ ಅಥವಾ ಕಂಪನಿಯ ಹೆಸರನ್ನು ಅನಧಿಕೃತ ಲಿಂಕ್‌ನಲ್ಲಿ ಬಳಸುತ್ತಿದೆ',
    RULE_TYPOSQUATTING: 'ಮೋಸ ಮಾಡಲು ನೈಜ ಬ್ರ್ಯಾಂಡ್ ಹೆಸರಿನ ಸ್ಪೆಲ್ಲಿಂಗ್ ಅನ್ನು ಬದಲಾಯಿಸಲಾಗಿದೆ',
    RULE_EXCESSIVE_SUBDOMAINS: 'ಅನಗತ್ಯವಾಗಿ ಅನೇಕ ಉಪ-ವಿಭಾಗಗಳನ್ನು ಹೊಂದಿರುವ ಗೊಂದಲದ ವಿಳಾಸ',
    RULE_NESTED_URL_IN_QUERY: 'ನಿಜವಾದ ವಿಳಾಸವನ್ನು ಮರೆಮಾಚಿ ಬೇರೆಡೆಗೆ ಮರುನಿರ್ದೇಶಿಸುವ ತಂತ್ರ',
    RULE_RISKY_EXTENSION: 'ಅಪಾಯಕಾರಿ ತಂತ್ರಾಂಶ ಅಥವಾ ವೈರಸ್ ಫೈಲ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡುವ ಪ್ರಯತ್ನ',
    RULE_SHORTENER_MASK: 'ನಿಜವಾದ ವೆಬ್‌ಸೈಟ್ ಅನ್ನು ಮರೆಮಾಚುವ ಸಂಕ್ಷಿಪ್ತ ಲಿಂಕ್ (Short link)',
    RULE_DOUBLE_SLASH_PATH: 'ವೆಬ್ ವಿಳಾಸದಲ್ಲಿ ಅಸಾಮಾನ್ಯ ಡಬಲ್ ಸ್ಲ್ಯಾಶ್ (//) ಇದೆ',
    RULE_NON_STANDARD_PORT: 'ಅಸಾಮಾನ್ಯ ತಾಂತ್ರಿಕ ಪೋರ್ಟ್ ಮೂಲಕ ಸಂಪರ್ಕಿಸುತ್ತಿದೆ',
    is_ip_host: 'ಹೆಸರಿಲ್ಲದ ಕೇವಲ ಸಂಖ್ಯೆಗಳ ವಿಳಾಸ',
    brand_mismatch: 'ಕಂಪನಿಯ ಹೆಸರು ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್‌ಗೆ ಹೊಂದಿಕೆಯಾಗುತ್ತಿಲ್ಲ',
    risky_file_extension: 'ಅಪಾಯಕಾರಿ ಕಂಪ್ಯೂಟರ್ ಫೈಲ್‌ಗೆ ದಾರಿತೋರಿಸುತ್ತಿದೆ',
    is_shortener: 'ನಿಜವಾದ ತಾಣವನ್ನು ಮರೆಮಾಚುವ ಶಾರ್ಟ್ ಲಿಂಕ್',
    tld_category: 'ಆನ್‌ಲೈನ್ ವಂಚನೆಗೆ ಹೆಚ್ಚಾಗಿ ಬಳಸಲಾಗುವ ಡೊಮೈನ್ ವಿಧ',
    suspicious_token_count: 'ಲಾಗಿನ್, OTP ಅಥವಾ ಪಾಸ್‌ವರ್ಡ್‌ನಂತಹ ಪ್ರಮುಖ ಪದಗಳನ್ನು ಒಳಗೊಂಡಿದೆ',
    subdomain_count: 'ಅನೇಕ ಸಬ್-ಡೊಮೇನ್‌ಗಳಿರುವ ಸಂಕೀರ್ಣ ವಿಳಾಸ',
    dot_count: 'ವಿಳಾಸದಲ್ಲಿ ಅತಿಯಾದ ಚುಕ್ಕೆಗಳು (.) ಇವೆ',
    url_length: 'ಅತಿಯಾದ ಉದ್ದದ ಮತ್ತು ಸಂಶಯಾಸ್ಪದ ವೆಬ್ ವಿಳಾಸ'
  },
  ml: {
    RULE_IP_HOST: 'യഥാർത്ഥ വെബ്‌സൈറ്റ് പേരിന് പകരം അക്കങ്ങൾ മാത്രമാണ് ഉപയോഗിച്ചിരിക്കുന്നത്',
    RULE_USERINFO_AT: "കബളിപ്പിക്കുന്നതിനായി '@' ചിഹ്നം ഉൾപ്പെടുത്തിയിരിക്കുന്നു",
    RULE_PUNYCODE_IDN: 'യഥാർത്ഥ സൈറ്റിന് സമാനമായി തോന്നുന്ന വ്യാജ അക്ഷരങ്ങൾ അടങ്ങിയിരിക്കുന്നു',
    RULE_BRAND_MISMATCH: 'പ്രമുഖ ബാങ്കിന്റെയോ കമ്പനിയുടെയോ പേര് അനധികൃത ലിങ്കിൽ ഉപയോഗിച്ചിരിക്കുന്നു',
    RULE_TYPOSQUATTING: 'കബളിപ്പിക്കാൻ വിശ്വസനീയമായ പേര് തെറ്റായ അക്ഷരവിന്യാസത്തിൽ നൽകിയിരിക്കുന്നു',
    RULE_EXCESSIVE_SUBDOMAINS: 'വളരെയധികം ഉപവിഭാഗങ്ങൾ (subdomains) അടങ്ങിയ നീളമുള്ള വെബ് വിലാസം',
    RULE_NESTED_URL_IN_QUERY: 'യഥാർത്ഥ വിലാസം മറച്ചുവെച്ച് മറ്റൊരു വിലാസത്തിലേക്ക് തിരിച്ചുവിടുന്നു',
    RULE_RISKY_EXTENSION: 'അപകടകരമായ വൈറസ് ഫയലോ പ്രോഗ്രാമോ ഡൗൺലോഡ് ചെയ്യാൻ ശ്രമിക്കുന്നു',
    RULE_SHORTENER_MASK: 'യഥാർത്ഥ വെബ്‌സൈറ്റ് എങ്ങോട്ടാണെന്ന് മറയ്ക്കുന്ന ചുരുക്കിയ ലിങ്ക്',
    RULE_DOUBLE_SLASH_PATH: 'വിലാസത്തിൽ അസാധാരണമായ ഇരട്ട സ്ലാഷുകൾ (//) കാണപ്പെടുന്നു',
    RULE_NON_STANDARD_PORT: 'അസാധാരണ നെറ്റ്‌വർക്ക് പോർട്ട് വഴിയാണ് കണക്റ്റ് ചെയ്യുന്നത്',
    is_ip_host: 'പേരില്ലാതെ അക്കങ്ങൾ മാത്രമുള്ള സാങ്കേതിക വിലാസം',
    brand_mismatch: 'സ്ഥാപനത്തിന്റെ പേര് ഔദ്യോഗിക വെബ്‌സൈറ്റുമായി പൊരുത്തപ്പെടുന്നില്ല',
    risky_file_extension: 'അപകടകരമായ കമ്പ്യൂട്ടർ ഫയലിലേക്ക് നയിക്കുന്നു',
    is_shortener: 'യഥാർത്ഥ ലക്ഷ്യം മറയ്ക്കുന്ന ഷോർട്ട് ലിങ്ക്',
    tld_category: 'ഓൺലൈൻ തട്ടിപ്പുകൾക്ക് വ്യാപകമായി ഉപയോഗിക്കുന്ന വെബ് ഡൊമെയ്ൻ',
    suspicious_token_count: 'ലോഗിൻ, ഒടിപി, പാസ്‌വേഡ് തുടങ്ങിയ നിർണായക വാക്കുകൾ അടങ്ങിയിരിക്കുന്നു',
    subdomain_count: 'നിരവധി സബ്-ഡൊമെയ്‌നുകൾ ഉള്ള സങ്കീർണ്ണ വിലാസം',
    dot_count: 'വിലാസത്തിൽ സാധാരണയിൽ കവിഞ്ഞ ഡോട്ടുകൾ (.) ഉണ്ട്',
    url_length: 'വളരെ നീളമുള്ളതും സംശയാസ്പദവുമായ വെബ് വിലാസം'
  }
};

/**
 * Extract human-readable detected indicators strictly from actual findings.
 * Never invents indicators not reported by rules, factors, or threat intel.
 */
export function extractFriendlyIndicators(ruleFlags = [], topFactors = [], intelResult = {}, language = 'en') {
  const lang = INDICATOR_DICTS[language] ? language : 'en';
  const indicatorMap = INDICATOR_DICTS[lang];
  const indicators = [];
  const seen = new Set();

  if (intelResult && intelResult.hit) {
    const intelMsgs = {
      en: 'Identified on active threat intelligence lists as a dangerous website',
      ta: 'அரசாங்க/சர்வதேச பாதுகாப்பு எச்சரிக்கைப் பட்டியலில் இந்த முகவரி உள்ளது',
      hi: 'सक्रिय साइबर सुरक्षा चेतावनी सूची में यह खतरनाक वेबसाइट के रूप में दर्ज है',
      te: 'యాక్టివ్ సైబర్ సెక్యూరిటీ బెదిరింపుల జాబితాలో ఇది ప్రమాదకరమైన సైట్‌గా గుర్తించబడింది',
      kn: 'ಸಕ್ರಿಯ ಸೈಬರ್ ಭದ್ರತಾ ಬೆದರಿಕೆ ಪಟ್ಟಿಯಲ್ಲಿ ಇದನ್ನು ಅಪಾಯಕಾರಿ ತಾಣವೆಂದು ಗುರುತಿಸಲಾಗಿದೆ',
      ml: 'സജീവ സൈബർ സുരക്ഷാ മുന്നറിയിപ്പ് പട്ടികയിൽ ഇത് അപകടകരമായ വെബ്‌സൈറ്റായി രേഖപ്പെടുത്തിയിട്ടുണ്ട്'
    };
    const intelText = intelMsgs[lang] || intelMsgs.en;
    indicators.push(intelText);
    seen.add(intelText);
  }

  for (const flag of ruleFlags) {
    const text = indicatorMap[flag.id] || flag.name || flag.id;
    if (text && !seen.has(text)) {
      indicators.push(text);
      seen.add(text);
    }
  }

  // Include top risk-increasing factors if not already represented
  if (topFactors && topFactors.length > 0) {
    for (const factor of topFactors) {
      if (factor.influence_type === 'risk_increasing') {
        const text = indicatorMap[factor.feature_name];
        if (text && !seen.has(text)) {
          indicators.push(text);
          seen.add(text);
        }
      }
    }
  }

  return indicators;
}

/**
 * Generate a deterministic NLP explanation tailored for elderly users across 6 languages.
 * Guarantees zero hallucinations, preserved verdict, and clear instructions.
 */
export function generateFallbackExplanation({
  verdict,
  score = 0,
  ruleFlags = [],
  topFactors = [],
  intelResult = {},
  language = 'en'
}) {
  const lang = INDICATOR_DICTS[language] ? language : 'en';
  const indicators = extractFriendlyIndicators(ruleFlags, topFactors, intelResult, lang);

  // Tamil (தமிழ்)
  if (lang === 'ta') {
    if (verdict === 'Safe') {
      return {
        language: 'ta',
        verdict: 'Safe',
        title: 'பாதுகாப்பான இணையதளம்',
        badge: 'குறைந்த ஆபத்து (Safe)',
        summary: 'இந்த இணையதள முகவரி சாதாரணமாகத் தெரிகிறது. சந்தேகத்திற்குரிய ஏமாற்று வேலைகள் எதுவும் இதில் தென்படவில்லை.',
        what_it_means: 'இந்த லிங்க் வழக்கமான இணையதள அமைப்பைக் கொண்டுள்ளது. ஏமாற்றும் வழிகளோ அல்லது அறியப்பட்ட அச்சுறுத்தல்களோ இதில் இல்லை.',
        what_to_do: 'இந்தப் பக்கத்தை நீங்கள் திறக்கலாம். ஆனாலும், எந்த ஒரு கணினி மென்பொருளும் 100% முழு உத்தரவாதம் அளிக்க முடியாது என்பதால் விழிப்புடன் இருக்கவும்.',
        elderly_advice: 'முக்கிய பாதுகாப்பு விதி: உங்கள் வங்கி PIN, OTP அல்லது கடவுச்சொல்லை (Password) தேவையின்றி யாரிடமும் பகிராதீர்கள்.',
        detected_points: indicators.length > 0 ? indicators : ['அறியப்பட்ட அச்சுறுத்தல் அறிகுறிகள் எதுவும் இல்லை'],
        message: 'இந்த லிங்க் சாதாரணமாகத் தெரிகிறது. ஆபத்தான அறிகுறிகள் எதுவும் தெரியவில்லை. எனினும் உங்கள் password அல்லது OTP-ஐ தேவையின்றி எங்கும் கொடுக்காதீர்கள்.',
        generated_by: 'deterministic_nlp_ta'
      };
    }
    if (verdict === 'Suspicious') {
      const pointStr = indicators.length > 0 ? `கவனிக்கப்பட்டவை: ${indicators.slice(0, 2).join(', ')}.` : '';
      return {
        language: 'ta',
        verdict: 'Suspicious',
        title: 'எச்சரிக்கை: சந்தேகத்திற்குரிய இணைப்பு',
        badge: 'கவனம் தேவை (Suspicious)',
        summary: 'இந்த லிங்க் சந்தேகமாக இருக்கிறது. இது போலியான இணையதளமாக இருக்கலாம். உங்கள் password அல்லது OTP-ஐ இதில் கொடுக்காதீர்கள். தேவையெனில் அதிகாரப்பூர்வ இணையதளத்தை நேரடியாகத் திறக்கவும்.',
        what_it_means: `இந்த முகவரியில் வழக்கத்திற்கு மாறான அமைப்புகள் அல்லது மறைக்கப்பட்ட விவரங்கள் உள்ளன. ${pointStr}`,
        what_to_do: 'இந்த பக்கத்தில் உங்கள் Password, OTP, வங்கி விவரங்கள் அல்லது மொபைல் எண்ணை ஒருபோதும் உள்ளிடாதீர்கள்.',
        elderly_advice: 'இந்த லிங்க் உங்களுக்கு SMS, WhatsApp அல்லது மின்னஞ்சலில் வந்திருந்தால், அதைத் தொடாதீர்கள். உங்கள் வங்கி அல்லது நிறுவனத்தின் அதிகாரப்பூர்வ இணையதளத்தை நேரடியாகத் திறந்து பார்க்கவும்.',
        detected_points: indicators.length > 0 ? indicators : ['வழக்கத்திற்கு மாறான முகவரி அமைப்பு'],
        message: 'இந்த லிங்க் சந்தேகமாக இருக்கிறது. இது போலியான இணையதளமாக இருக்கலாம். உங்கள் password அல்லது OTP-ஐ இதில் கொடுக்காதீர்கள். தேவையெனில் அதிகாரப்பூர்வ இணையதளத்தை நேரடியாகத் திறக்கவும்.',
        generated_by: 'deterministic_nlp_ta'
      };
    }
    // Malicious
    const pointStr = indicators.length > 0 ? `கண்டறியப்பட்ட ஆபத்துகள்: ${indicators.slice(0, 2).join(', ')}.` : '';
    return {
      language: 'ta',
      verdict: 'Malicious',
      title: 'ஆபத்து: தீங்கிழைக்கும் தளம்',
      badge: 'மிக அதிக ஆபத்து (Malicious)',
      summary: 'இந்த லிங்க் மிகவும் ஆபத்தானது. உங்கள் பணத்தையோ அல்லது தனிப்பட்ட தகவல்களையோ திருட இது உருவாக்கப்பட்டிருக்கலாம். இந்த லிங்கை திறக்காதீர்கள், உடனே இந்த பக்கத்தை மூடிவிடுங்கள்.',
      what_it_means: `இது மோசடி அல்லது வைரஸ் பரப்பும் இணையதளம் என அடையாளம் காணப்பட்டுள்ளது. ${pointStr}`,
      what_to_do: 'இந்த லிங்கைத் திறக்காதீர்கள். உடனே இந்தப் பக்கத்தை மூடிவிடுங்கள். எதையும் டவுன்லோட் செய்யாதீர்கள்.',
      elderly_advice: 'ஒருபோதும் இதில் உங்கள் கார்டு எண், PIN அல்லது OTP கொடுக்காதீர்கள். ஏதேனும் தவறு நேர்ந்தால் உடனடியாக உங்கள் குடும்பத்தினர் அல்லது வங்கியின் உதவி எண்ணை அழைக்கவும்.',
      detected_points: indicators.length > 0 ? indicators : ['உறுதிப்படுத்தப்பட்ட மோசடி அல்லது போலி இணையதளம்'],
      message: 'இந்த லிங்க் மிகவும் ஆபத்தானது. உங்கள் password அல்லது OTP-ஐ ஒருபோதும் இதில் கொடுக்காதீர்கள். உடனே இந்த பக்கத்தை மூடிவிடுங்கள்.',
      generated_by: 'deterministic_nlp_ta'
    };
  }

  // Hindi (हिन्दी)
  if (lang === 'hi') {
    if (verdict === 'Safe') {
      return {
        language: 'hi',
        verdict: 'Safe',
        title: 'सुरक्षित वेब लिंक',
        badge: 'कम जोखिम (Safe)',
        summary: 'यह लिंक सामान्य और सुरक्षित प्रतीत होता है। इसमें किसी धोखाधड़ी के स्पष्ट संकेत नहीं मिले हैं।',
        what_it_means: 'इस वेब पते की बनावट सामान्य वेबसाइटों जैसी है। इसमें कोई छुपे हुए खतरे नहीं पाए गए।',
        what_to_do: 'आप इस वेबसाइट पर जा सकते हैं। ध्यान रखें कि कोई भी स्वचालित प्रणाली 100% गारंटी नहीं दे सकती, इसलिए सतर्कता बनाए रखें।',
        elderly_advice: 'बुजुर्गों के लिए सलाह: कभी भी किसी अपरिचित पेज पर अपना बैंक पासवर्ड, एटीएम पिन या ओटीपी साझा न करें।',
        detected_points: indicators.length > 0 ? indicators : ['कोई संदिग्ध या हानिकारक संकेत नहीं मिला'],
        message: 'यह लिंक सामान्य दिखता है। कोई हानिकारक लक्षण नहीं मिले। फिर भी अपना पासवर्ड या बैंक ओटीपी किसी अनजान पेज पर कभी न डालें।',
        generated_by: 'deterministic_nlp_hi'
      };
    }
    if (verdict === 'Suspicious') {
      const pointStr = indicators.length > 0 ? `पाए गए संकेत: ${indicators.slice(0, 2).join(', ')}।` : '';
      return {
        language: 'hi',
        verdict: 'Suspicious',
        title: 'चेतावनी: संदिग्ध लिंक',
        badge: 'सावधानी बरतें (Suspicious)',
        summary: 'यह लिंक असामान्य लग रहा है और यह नकली वेबसाइट हो सकती है। इसमें अपना पासवर्ड या ओटीपी न डालें। आधिकारिक वेबसाइट को सीधे खोलें।',
        what_it_means: `इस वेब पते में धोखाधड़ी या भ्रमित करने वाले संकेत मिले हैं। ${pointStr}`,
        what_to_do: 'इस पेज पर अपना पासवर्ड, बैंक खाता विवरण, कार्ड नंबर या ओटीपी बिल्कुल न भरें।',
        elderly_advice: 'यदि यह लिंक व्हाट्सएप, एसएमएस या अज्ञात ईमेल पर आया है, तो इसे न खोलें। सीधे अपने बैंक की शाखा या आधिकारिक ऐप का उपयोग करें।',
        detected_points: indicators.length > 0 ? indicators : ['असामान्य वेब संरचना और बढ़ा हुआ जोखिम'],
        message: 'यह लिंक असामान्य लग रहा है और यह नकली वेबसाइट हो सकती है। इसमें अपना पासवर्ड या ओटीपी न डालें। आधिकारिक वेबसाइट को सीधे खोलें।',
        generated_by: 'deterministic_nlp_hi'
      };
    }
    // Malicious
    const pointStr = indicators.length > 0 ? `पहचाने गए खतरे: ${indicators.slice(0, 2).join(', ')}।` : '';
    return {
      language: 'hi',
      verdict: 'Malicious',
      title: 'खतरा: दुर्भावनापूर्ण (Malicious) लिंक',
      badge: 'अत्यधिक जोखिम (Malicious)',
      summary: 'यह लिंक बेहद खतरनाक है और इसे आपकी निजी जानकारी या पैसे चुराने के लिए बनाया गया है। इसे तुरंत बंद करें और किसी भी चीज़ पर क्लिक न करें।',
      what_it_means: `यह लिंक प्रमाणित ऑनलाइन फ्रॉड, फिशिंग या वायरस फैलाने वाली श्रेणी में आता है। ${pointStr}`,
      what_to_do: 'इस लिंक को तुरंत बंद कर दें। कोई भी फाइल डाउनलोड न करें और कोई विवरण न भरें।',
      elderly_advice: 'अपना पासवर्ड या बैंक ओटीपी कभी दर्ज न करें। यदि आपने गलती से कोई विवरण भर दिया है, तो तुरंत अपने बैंक हेल्पलाइन या परिजनों से संपर्क करें।',
      detected_points: indicators.length > 0 ? indicators : ['प्रमाणित धोखाधड़ी या साइबर हमले के लक्षण'],
      message: 'यह लिंक बेहद खतरनाक है और धोखाधड़ी के लिए बनाया गया है। इसमें पासवर्ड या ओटीपी कभी न दें और इस पेज को तुरंत बंद कर दें।',
      generated_by: 'deterministic_nlp_hi'
    };
  }

  // Telugu (తెలుగు)
  if (lang === 'te') {
    if (verdict === 'Safe') {
      return {
        language: 'te',
        verdict: 'Safe',
        title: 'సురక్షితమైన వెబ్ చిరునామా',
        badge: 'తక్కువ ప్రమాదం (Safe)',
        summary: 'ఈ వెబ్‌సైట్ లింక్ సాధారణంగా కనిపిస్తోంది. ఇందులో ఎటువంటి మోసపూరిత గుర్తులు కనిపించలేదు.',
        what_it_means: 'ఈ లింక్ ప్రామాణిక వెబ్‌సైట్ నిర్మాణాన్ని కలిగి ఉంది. తెలిసిన సైబర్ ముప్పులు ఏవీ లేవు.',
        what_to_do: 'మీరు ఈ పేజీని తెరవవచ్చు. ఏ ఆటోమేటెడ్ టూల్ కూడా 100% గ్యారెంటీ ఇవ్వలేదని గుర్తుంచుకోండి, అప్రమత్తంగా ఉండండి.',
        elderly_advice: 'ముఖ్యమైన భద్రతా నియమం: మీ బ్యాంక్ పిన్, పాస్‌వర్డ్ లేదా OTP ని తెలియని వారితో ఎప్పుడూ పంచుకోవద్దు.',
        detected_points: indicators.length > 0 ? indicators : ['ఎటువంటి ప్రమాదకర సంకేతాలు గుర్తించబడలేదు'],
        message: 'ఈ లింక్ సాధారణంగా కనిపిస్తోంది. ప్రమాదకర సంకేతాలు లేవు. అయినప్పటికీ మీ పాస్‌వర్డ్ లేదా OTP ని ఎవరికీ ఇవ్వకండి.',
        generated_by: 'deterministic_nlp_te'
      };
    }
    if (verdict === 'Suspicious') {
      const pointStr = indicators.length > 0 ? `గుర్తించిన అంశాలు: ${indicators.slice(0, 2).join(', ')}.` : '';
      return {
        language: 'te',
        verdict: 'Suspicious',
        title: 'హెచ్చరిక: అనుమానాస్పద లింక్',
        badge: 'జాగ్రత్త అవసరం (Suspicious)',
        summary: 'ఈ లింక్ అనుమానాస్పదంగా ఉంది మరియు నకిలీ వెబ్‌సైట్ కావచ్చు. మీ పాస్‌వర్డ్ లేదా OTP ని ఇందులో నమోదు చేయవద్దు. అధికారిక వెబ్‌సైట్‌ను నేరుగా తెరవండి.',
        what_it_means: `ఈ చిరునామాలో అసాధారణ లేదా దాచిన లక్షణాలు ఉన్నాయి. ${pointStr}`,
        what_to_do: 'ఈ పేజీలో మీ పాస్‌వర్డ్, బ్యాంక్ వివరాలు, కార్డు నంబర్ లేదా OTP ని ఎట్టిపరిస్థితుల్లోనూ నమోదు చేయవద్దు.',
        elderly_advice: 'ఈ లింక్ మీకు SMS లేదా వాట్సాప్‌లో వచ్చి ఉంటే క్లిక్ చేయవద్దు. అవసరమైతే మీ బ్యాంక్ లేదా సంస్థ అధికారిక వెబ్‌సైట్‌ను నేరుగా సందర్శించండి.',
        detected_points: indicators.length > 0 ? indicators : ['అసాధారణ వెబ్ చిరునామా నిర్మాణం'],
        message: 'ఈ లింక్ అనుమానాస్పదంగా ఉంది మరియు నకిలీ వెబ్‌సైట్ కావచ్చు. మీ పాస్‌వర్డ్ లేదా OTP ని ఇందులో నమోదు చేయవద్దు. అధికారిక వెబ్‌సైట్‌ను నేరుగా తెరవండి.',
        generated_by: 'deterministic_nlp_te'
      };
    }
    // Malicious
    const pointStr = indicators.length > 0 ? `గుర్తించబడిన ప్రమాదాలు: ${indicators.slice(0, 2).join(', ')}.` : '';
    return {
      language: 'te',
      verdict: 'Malicious',
      title: 'ప్రమాదం: హానికరమైన (Malicious) వెబ్‌సైట్',
      badge: 'అధిక ప్రమాదం (Malicious)',
      summary: 'ఈ లింక్ చాలా ప్రమాదకరమైనది. మీ డబ్బు లేదా వ్యక్తిగత సమాచారాన్ని దొంగిలించడానికి ఇది సృష్టించబడింది. దీన్ని వెంటనే మూసివేయండి.',
      what_it_means: `ఇది మోసపూరిత ఫిషింగ్ లేదా వైరస్ కలిగిన సైట్‌గా నిర్ధారించబడింది. ${pointStr}`,
      what_to_do: 'ఈ లింక్‌ను తెరవవద్దు. వెంటనే ఈ విండోను మూసివేయండి. ఏ ఫైల్‌ను డౌన్‌లోడ్ చేయవద్దు.',
      elderly_advice: 'మీ కార్డ్ వివరాలు లేదా OTP ని ఎప్పుడూ ఇవ్వకండి. ఒకవేళ పొరపాటున వివరాలు ఇచ్చి ఉంటే వెంటనే మీ బ్యాంక్ హెల్ప్‌లైన్‌ను సంప్రదించండి.',
      detected_points: indicators.length > 0 ? indicators : ['నిర్ధారించబడిన సైబర్ దాడి లక్షణాలు'],
      message: 'ఈ లింక్ చాలా ప్రమాదకరమైనది. మీ పాస్‌వర్డ్ లేదా OTP ని ఎప్పుడూ నమోదు చేయవద్దు. వెంటనే ఈ పేజీని మూసివేయండి.',
      generated_by: 'deterministic_nlp_te'
    };
  }

  // Kannada (ಕನ್ನಡ)
  if (lang === 'kn') {
    if (verdict === 'Safe') {
      return {
        language: 'kn',
        verdict: 'Safe',
        title: 'ಸುರಕ್ಷಿತ ವೆಬ್ ವಿಳಾಸ',
        badge: 'ಕಡಿಮೆ ಅಪಾಯ (Safe)',
        summary: 'ಈ ವೆಬ್‌ಸೈಟ್ ಲಿಂಕ್ ಸಹಜವಾಗಿ ಕಾಣುತ್ತಿದೆ. ಇದರಲ್ಲಿ ಯಾವುದೇ ಮೋಸದ ಲಕ್ಷಣಗಳು ಕಂಡುಬಂದಿಲ್ಲ.',
        what_it_means: 'ಈ ವಿಳಾಸವು ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್‌ಗಳ ನಿಯಮಿತ ರಚನೆಯನ್ನು ಹೊಂದಿದೆ. ಯಾವುದೇ ಮೋಸದ ತಂತ್ರಗಳಿಲ್ಲ.',
        what_to_do: 'ನೀವು ಈ ಪುಟವನ್ನು ತೆರೆಯಬಹುದು. ಯಾವುದೇ ಸಾಫ್ಟ್‌ವೇರ್ 100% ಗ್ಯಾರಂಟಿ ನೀಡಲು ಸಾಧ್ಯವಿಲ್ಲ ಎಂಬುದು ನೆನಪಿರಲಿ, ಜಾಗರೂಕರಾಗಿರಿ.',
        elderly_advice: 'ಹಿರಿಯರಿಗೆ ಪ್ರಮುಖ ನಿಯಮ: ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಪಿನ್, ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ ಒಟಿಪಿ (OTP) ಅನ್ನು ಯಾರೊಂದಿಗೂ ಹಂಚಿಕೊಳ್ಳಬೇಡಿ.',
        detected_points: indicators.length > 0 ? indicators : ['ಯಾವುದೇ ಅಪಾಯಕಾರಿ ಅಂಶಗಳು ಕಂಡುಬಂದಿಲ್ಲ'],
        message: 'ಈ ಲಿಂಕ್ ಸಹಜವಾಗಿ ಕಾಣುತ್ತಿದೆ. ಯಾವುದೇ ಅಪಾಯಕಾರಿ ಅಂಶಗಳಿಲ್ಲ. ಆದಾಗ್ಯೂ ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ಅನ್ನು ಅಪರಿಚಿತ ಪುಟಗಳಲ್ಲಿ ನಮೂದಿಸಬೇಡಿ.',
        generated_by: 'deterministic_nlp_kn'
      };
    }
    if (verdict === 'Suspicious') {
      const pointStr = indicators.length > 0 ? `ಗಮನಿಸಲಾದ ಅಂಶಗಳು: ${indicators.slice(0, 2).join(', ')}.` : '';
      return {
        language: 'kn',
        verdict: 'Suspicious',
        title: 'ಎಚ್ಚರಿಕೆ: ಸಂಶಯಾಸ್ಪದ ಲಿಂಕ್',
        badge: 'ಎಚ್ಚರಿಕೆ ಅಗತ್ಯ (Suspicious)',
        summary: 'ಈ ಲಿಂಕ್ ಅಸಹಜವಾಗಿದೆ ಮತ್ತು ನಕಲಿ ವೆಬ್‌ಸೈಟ್ ಆಗಿರಬಹುದು. ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ಅನ್ನು ನಮೂದಿಸಬೇಡಿ. ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್ ಅನ್ನು ನೇರವಾಗಿ ತೆರೆಯಿರಿ.',
        what_it_means: `ಈ ವೆಬ್ ವಿಳಾಸದಲ್ಲಿ ಮೋಸದ ಅಥವಾ ಅಸಹಜ ಲಕ್ಷಣಗಳಿವೆ. ${pointStr}`,
        what_to_do: 'ಈ ಪುಟದಲ್ಲಿ ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್, ಬ್ಯಾಂಕಿಂಗ್ ವಿವರಗಳು ಅಥವಾ OTP ಅನ್ನು ಯಾವುದೇ ಕಾರಣಕ್ಕೂ ನಮೂದಿಸಬೇಡಿ.',
        elderly_advice: 'ಈ ಲಿಂಕ್ ವಾಟ್ಸಾಪ್ ಅಥವಾ ಎಸ್ಎಂಎಸ್‌ನಲ್ಲಿ ಬಂದಿದ್ದರೆ ಅದನ್ನು ಮುಟ್ಟಬೇಡಿ. ನಿಮ್ಮ ಬ್ಯಾಂಕಿನ ಅಧಿಕೃತ ಆ್ಯಪ್ ಅಥವಾ ವೆಬ್‌ಸೈಟ್ ಅನ್ನು ನೇರವಾಗಿ ಬಳಸಿ.',
        detected_points: indicators.length > 0 ? indicators : ['ಅಸಹಜ ವಿಳಾಸ ರಚನೆ'],
        message: 'ಈ ಲಿಂಕ್ ಅಸಹಜವಾಗಿದೆ ಮತ್ತು ನಕಲಿ ವೆಬ್‌ಸೈಟ್ ಆಗಿರಬಹುದು. ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ಅನ್ನು ನಮೂದಿಸಬೇಡಿ. ಅಧಿಕೃತ ವೆಬ್‌ಸೈಟ್ ಅನ್ನು ನೇರವಾಗಿ ತೆರೆಯಿರಿ.',
        generated_by: 'deterministic_nlp_kn'
      };
    }
    // Malicious
    const pointStr = indicators.length > 0 ? `ಕಂಡುಬಂದ ಅಪಾಯಗಳು: ${indicators.slice(0, 2).join(', ')}.` : '';
    return {
      language: 'kn',
      verdict: 'Malicious',
      title: 'ಅಪಾಯ: ಹಾನಿಕಾರಕ ವೆಬ್‌ಸೈಟ್ (Malicious)',
      badge: 'ಅತಿ ಹೆಚ್ಚು ಅಪಾಯ (Malicious)',
      summary: 'ಈ ಲಿಂಕ್ ಅತ್ಯಂತ ಅಪಾಯಕಾರಿಯಾಗಿದೆ. ನಿಮ್ಮ ಹಣ ಅಥವಾ ವೈಯಕ್ತಿಕ ಮಾಹಿತಿಯನ್ನು ಕದಿಯಲು ಇದನ್ನು ರಚಿಸಲಾಗಿದೆ. ತಕ್ಷಣವೇ ಈ ಪುಟವನ್ನು ಮುಚ್ಚಿ.',
      what_it_means: `ಇದು ವಂಚನೆ ಅಥವಾ ವೈರಸ್ ಹರಡುವ ತಾಣವೆಂದು ದೃಢಪಟ್ಟಿದೆ. ${pointStr}`,
      what_to_do: 'ಈ ಲಿಂಕ್ ಅನ್ನು ತೆರೆಯಬೇಡಿ. ಯಾವುದೇ ಫೈಲ್ ಡೌನ್‌ಲೋಡ್ ಮಾಡಬೇಡಿ. ತಕ್ಷಣವೇ ಈ ಪುಟವನ್ನು ಮುಚ್ಚಿ.',
      elderly_advice: 'ಯಾವುದೇ ವಿವರ ನೀಡಬೇಡಿ. ಈಗಾಗಲೇ ನಮೂದಿಸಿದ್ದರೆ ತಕ್ಷಣ ನಿಮ್ಮ ಬ್ಯಾಂಕ್ ಹೆಲ್ಪ್‌ಲೈನ್ ಅಥವಾ ಕುಟುಂಬದವರನ್ನು ಸಂಪರ್ಕಿಸಿ.',
      detected_points: indicators.length > 0 ? indicators : ['ದೃಢಪಟ್ಟ ಆನ್‌ಲೈನ್ ವಂಚನೆ'],
      message: 'ಈ ಲಿಂಕ್ ಅತ್ಯಂತ ಅಪಾಯಕಾರಿಯಾಗಿದೆ. ನಿಮ್ಮ ಪಾಸ್‌ವರ್ಡ್ ಅಥವಾ OTP ಅನ್ನು ಎಂದಿಗೂ ನೀಡಬೇಡಿ. ತಕ್ಷಣವೇ ಈ ಪುಟವನ್ನು ಮುಚ್ಚಿ.',
      generated_by: 'deterministic_nlp_kn'
    };
  }

  // Malayalam (മലയാളം)
  if (lang === 'ml') {
    if (verdict === 'Safe') {
      return {
        language: 'ml',
        verdict: 'Safe',
        title: 'സുരക്ഷിതമായ വെബ് വിലാസം',
        badge: 'കുറഞ്ഞ അപകടസാധ്യത (Safe)',
        summary: 'ഈ വെബ്‌സൈറ്റ് ലിങ്ക് സാധാരണമായി കാണപ്പെടുന്നു. സംശയാസ്പദമായ തട്ടിപ്പുകളൊന്നും ഇതിൽ കണ്ടെത്തിയിട്ടില്ല.',
        what_it_means: 'ഈ ലിങ്ക് സാധാരണ വെബ്‌സൈറ്റുകളുടെ ഘടനയിലാണ്. സുരക്ഷാ ഭീഷണികളൊന്നും റിപ്പോർട്ട് ചെയ്തിട്ടില്ല.',
        what_to_do: 'നിങ്ങൾക്ക് ഈ പേജ് തുറക്കാവുന്നതാണ്. ഒരു സോഫ്റ്റ്‌വെയറിനും 100% ഗ്യാരണ്ടി നൽകാൻ കഴിയില്ല എന്നതിനാൽ ജാഗ്രത പാലിക്കുക.',
        elderly_advice: 'പ്രധാന സുരക്ഷാ നിർദ്ദേശം: നിങ്ങളുടെ ബാങ്ക് പിൻ, പാസ്‌വേഡ് അല്ലെങ്കിൽ ഒടിപി (OTP) ആരുമായും പങ്കിടരുത്.',
        detected_points: indicators.length > 0 ? indicators : ['അപകടകരമായ ലക്ഷണങ്ങളൊന്നും കണ്ടെത്തിയില്ല'],
        message: 'ഈ ലിങ്ക് സാധാരണമായി കാണപ്പെടുന്നു. അപകടകരമായ ലക്ഷണങ്ങളില്ല. എങ്കിലും പാസ്‌വേഡ് അല്ലെങ്കിൽ OTP ആവശ്യമില്ലാതെ ആർക്കും നൽകരുത്.',
        generated_by: 'deterministic_nlp_ml'
      };
    }
    if (verdict === 'Suspicious') {
      const pointStr = indicators.length > 0 ? `ശ്രദ്ധയിൽപ്പെട്ടവ: ${indicators.slice(0, 2).join(', ')}.` : '';
      return {
        language: 'ml',
        verdict: 'Suspicious',
        title: 'മുന്നറിയിപ്പ്: സംശയാസ്പദമായ ലിങ്ക്',
        badge: 'ശ്രദ്ധിക്കുക (Suspicious)',
        summary: 'ഈ ലിങ്ക് സംശയാസ്പദമാണ്, ഇത് വ്യാജ വെബ്‌സൈറ്റ് ആകാൻ സാധ്യതയുണ്ട്. പാസ്‌വേഡോ ഒടിപിയോ ഇതിൽ നൽകരുത്. ഔദ്യോഗിക വെബ്‌സൈറ്റ് നേരിട്ട് തുറക്കുക.',
        what_it_means: `ഈ വെബ് വിലാസത്തിൽ അസാധാരണമായ ഘടനയുണ്ട്. ${pointStr}`,
        what_to_do: 'ഈ പേജിൽ നിങ്ങളുടെ പാസ്‌വേഡ്, ഒടിപി, ബാങ്ക് വിവരങ്ങൾ എന്നിവ ഒരിക്കലും നൽകരുത്.',
        elderly_advice: 'ഈ ലിങ്ക് വാട്ട്‌സ്ആപ്പിലോ എസ്എംഎസിലോ വന്നതാണെങ്കിൽ ക്ലിക്ക് ചെയ്യരുത്. ബാങ്കിന്റെ ഔദ്യോഗിക ആപ്പ് നേരിട്ട് തുറക്കുക.',
        detected_points: indicators.length > 0 ? indicators : ['അസാധാരണ വിലാസ ഘടന'],
        message: 'ഈ ലിങ്ക് സംശയാസ്പദമാണ്, ഇത് വ്യാജ വെബ്‌സൈറ്റ് ആകാൻ സാധ്യതയുണ്ട്. പാസ്‌വേഡോ ഒടിപിയോ ഇതിൽ നൽകരുത്. ഔദ്യോഗിക വെബ്‌സൈറ്റ് നേരിട്ട് തുറക്കുക.',
        generated_by: 'deterministic_nlp_ml'
      };
    }
    // Malicious
    const pointStr = indicators.length > 0 ? `കണ്ടെത്തിയ അപകടങ്ങൾ: ${indicators.slice(0, 2).join(', ')}.` : '';
    return {
      language: 'ml',
      verdict: 'Malicious',
      title: 'അപകടം: ദോഷകരമായ വെബ്‌സൈറ്റ് (Malicious)',
      badge: 'വളരെ ഉയർന്ന അപകടം (Malicious)',
      summary: 'ഈ ലിങ്ക് വളരെ അപകടകരമാണ്. നിങ്ങളുടെ പണമോ വ്യക്തിഗത വിവരങ്ങളോ മോഷ്ടിക്കാൻ നിർമ്മിച്ചതാകാം. ഈ ലിങ്ക് ഉടൻ തന്നെ അടയ്ക്കുക.',
      what_it_means: `ഇത് തട്ടിപ്പോ വൈറസോ ഉള്ള സൈറ്റായി സ്ഥിരീകരിച്ചിരിക്കുന്നു. ${pointStr}`,
      what_to_do: 'ഈ ലിങ്ക് തുറക്കരുത്. പേജ് ഉടൻ ക്ലോസ് ചെയ്യുക. യാതൊരു ഫയലുകളും ഡൗൺലോഡ് ചെയ്യരുത്.',
      elderly_advice: 'പാസ്‌വേഡോ ഒടിപിയോ നൽകരുത്. വിവരങ്ങൾ നൽകിയിട്ടുണ്ടെങ്കിൽ ഉടൻ തന്നെ ബാങ്കിലോ കുടുംബാംഗങ്ങളെയോ ബന്ധപ്പെടുക.',
      detected_points: indicators.length > 0 ? indicators : ['സ്ഥിരീകരിച്ച സൈബർ തട്ടിപ്പ്'],
      message: 'ഈ ലിങ്ക് വളരെ അപകടകരമാണ്. നിങ്ങളുടെ പാസ്‌വേഡോ ഒടിപിയോ ഒരിക്കലും നൽകരുത്. ഈ പേജ് ഉടൻ തന്നെ ക്ലോസ് ചെയ്യുക.',
      generated_by: 'deterministic_nlp_ml'
    };
  }

  // English fallback (default)
  if (verdict === 'Safe') {
    return {
      language: 'en',
      verdict: 'Safe',
      title: 'Safe Web Address',
      badge: 'Low Risk (Safe)',
      summary: 'This link looks normal and does not show common signs of a fake website.',
      what_it_means: 'The address structure matches standard, legitimate websites with no known deception tricks found.',
      what_to_do: 'You can visit this page. Remember that no automated tool can offer a 100% guarantee, so always maintain normal security habits.',
      elderly_advice: 'Always remember: Never share your bank PIN, password, or one-time code (OTP) unless you are completely sure of who you are dealing with.',
      detected_points: indicators.length > 0 ? indicators : ['No malicious signatures or deception patterns detected'],
      message: 'This link looks normal and no suspicious indicators were identified. Remember that no tool can give a 100% guarantee; never share your bank PIN or OTP on unfamiliar pages.',
      generated_by: 'deterministic_nlp_en'
    };
  }

  if (verdict === 'Suspicious') {
    const pointStr = indicators.length > 0 ? `Unusual items found: ${indicators.slice(0, 2).join(', ')}.` : '';
    return {
      language: 'en',
      verdict: 'Suspicious',
      title: 'Warning: Suspicious Link',
      badge: 'Caution Recommended (Suspicious)',
      summary: 'This link looks unusual and may lead to a fake website. Do not enter your password or OTP. Open the official website directly if you need to check your account.',
      what_it_means: `The web address has unusual or masked characteristics. ${pointStr}`,
      what_to_do: 'Do not enter your password, OTP, ATM pin, card details, or personal information on this page.',
      elderly_advice: 'If you received this link in a text message, WhatsApp, or unexpected email, do not click it. Open your official bank app or website directly instead.',
      detected_points: indicators.length > 0 ? indicators : ['Unusual address structure and elevated risk score'],
      message: 'This link looks unusual and may lead to a fake website. Do not enter your password or OTP. Open the official website directly if you need to check your account.',
      generated_by: 'deterministic_nlp_en'
    };
  }

  // Malicious
  const pointStr = indicators.length > 0 ? `Confirmed risk factors: ${indicators.slice(0, 2).join(', ')}.` : '';
  return {
    language: 'en',
    verdict: 'Malicious',
    title: 'Danger: Malicious Web Address',
    badge: 'High Risk Threat (Malicious)',
    summary: 'This link is dangerous and likely created to steal your money or passwords. Do not click it, do not enter passwords or OTPs, and close this page immediately.',
    what_it_means: `The address matches known malicious attack signatures or fraudulent spoofing. ${pointStr}`,
    what_to_do: 'Do not click or open this link. Close this window immediately. Do not download any file.',
    elderly_advice: 'Never enter passwords, PINs, or card numbers. If you already clicked this link, immediately contact your bank or a trusted family member for assistance.',
    detected_points: indicators.length > 0 ? indicators : ['Known attack signatures or confirmed threat feed match'],
    message: 'This link is dangerous and likely created to steal your money or passwords. Do not click it, do not enter passwords or OTPs, and close this page immediately.',
    generated_by: 'deterministic_nlp_en'
  };
}

const LANGUAGE_NAMES = {
  en: 'English',
  ta: 'Tamil (தமிழ்)',
  hi: 'Hindi (हिन्दी)',
  te: 'Telugu (తెలుగు)',
  kn: 'Kannada (ಕನ್ನಡ)',
  ml: 'Malayalam (മലയാളം)'
};

// In-memory explanation cache to minimize API calls and conserve quota
const explanationCache = new Map();
const MAX_CACHE_SIZE = 200;

// Circuit breaker for Gemini API quota limits (429 / RESOURCE_EXHAUSTED)
let quotaCooldownUntil = 0;

/**
 * Main Explainer: Attempts Gemini API (gemini-3.8-flash) if GEMINI_API_KEY is available
 * and quota is healthy, with seamless automatic fallback to the deterministic engine.
 */
export async function generateSimpleExplanation({
  verdict,
  score = 0,
  ruleFlags = [],
  topFactors = [],
  intelResult = {},
  language = 'en',
  url = ''
}) {
  const lang = INDICATOR_DICTS[language] ? language : 'en';
  const apiKey = process.env.GEMINI_API_KEY;

  // Check cache first
  const cacheKey = `${url || ''}|${verdict}|${lang}|${Number(score).toFixed(2)}`;
  if (explanationCache.has(cacheKey)) {
    return explanationCache.get(cacheKey);
  }

  // If no Gemini API key configured or quota is on cooldown, use deterministic engine immediately
  const isCooldownActive = Date.now() < quotaCooldownUntil;
  if (!apiKey || isCooldownActive) {
    const fallback = generateFallbackExplanation({
      verdict,
      score,
      ruleFlags,
      topFactors,
      intelResult,
      language: lang
    });
    // Store in cache
    if (explanationCache.size < MAX_CACHE_SIZE) {
      explanationCache.set(cacheKey, fallback);
    }
    return fallback;
  }

  try {
    const ai = new GoogleGenAI({
      apiKey,
      httpOptions: {
        headers: {
          'User-Agent': 'aistudio-build'
        }
      }
    });

    const detectedIndicators = extractFriendlyIndicators(ruleFlags, topFactors, intelResult, lang);
    const indicatorText = detectedIndicators.length > 0 ? detectedIndicators.join('; ') : 'None';
    const langLabel = LANGUAGE_NAMES[lang] || 'English';

    const prompt = `
You are an empathetic cybersecurity safety explainer for elderly and non-technical users in India and worldwide.
Translate the following technical URL detection result into a short, calm, easy-to-understand explanation in ${langLabel}.

Target Language: ${langLabel}
URL Verdict: ${verdict} (MUST NOT BE CHANGED UNDER ANY CIRCUMSTANCES)
Risk Score: ${Number(score).toFixed(4)}
Actual Identified Indicators: ${indicatorText}

STRICT SAFETY CONSTRAINTS:
1. PRESERVE the exact verdict: "${verdict}". Never contradict it or use a different verdict.
2. NEVER invent indicators that were not listed above. Only explain what was actually identified.
3. NEVER say a link is 100% safe or guaranteed safe.
4. For Suspicious or Malicious links, explicitly advise NOT to enter passwords, OTPs, PINs, or banking details.
5. Use short, simple sentences. Avoid complex technical jargon (do NOT use words like "heuristics", "entropy", "punycode", "vectors", "tokens").
6. Write naturally in the target script for Indian languages.
7. Respond strictly in valid JSON with these exact keys:
{
  "title": "short heading in target language",
  "summary": "1-2 sentence plain summary in target language",
  "what_it_means": "1 simple sentence explaining what was found",
  "what_to_do": "clear instruction on what the user should do next",
  "elderly_advice": "calm advice regarding passwords, OTPs, or contacting family/bank",
  "message": "one single standalone paragraph summarizing the warning and next step"
}
`;

    const generatePromise = ai.models.generateContent({
      model: 'gemini-3.8-flash',
      contents: prompt,
      config: {
        responseMimeType: 'application/json',
        temperature: 0.1
      }
    });

    const timeoutPromise = new Promise((_, reject) => {
      setTimeout(() => reject(new Error('AI explanation generation timed out (4000ms ceiling)')), 4000);
    });

    const response = await Promise.race([generatePromise, timeoutPromise]);
    const parsed = JSON.parse(response.text.trim());

    const badgeMap = {
      en: { Safe: 'Low Risk (Safe)', Suspicious: 'Caution Recommended (Suspicious)', Malicious: 'High Risk Threat (Malicious)' },
      ta: { Safe: 'குறைந்த ஆபத்து (Safe)', Suspicious: 'கவனம் தேவை (Suspicious)', Malicious: 'மிக அதிக ஆபத்து (Malicious)' },
      hi: { Safe: 'कम जोखिम (Safe)', Suspicious: 'सावधानी बरतें (Suspicious)', Malicious: 'अत्यधिक जोखिम (Malicious)' },
      te: { Safe: 'తక్కువ ప్రమాదం (Safe)', Suspicious: 'జాగ్రత్త అవసరం (Suspicious)', Malicious: 'అధిక ప్రమాదం (Malicious)' },
      kn: { Safe: 'ಕಡಿಮೆ ಅಪಾಯ (Safe)', Suspicious: 'ಎಚ್ಚರಿಕೆ ಅಗತ್ಯ (Suspicious)', Malicious: 'ಅತಿ ಹೆಚ್ಚು ಅಪಾಯ (Malicious)' },
      ml: { Safe: 'കുറഞ്ഞ അപകടസാധ്യത (Safe)', Suspicious: 'ശ്രദ്ധിക്കുക (Suspicious)', Malicious: 'വളരെ ഉയർന്ന അപകടം (Malicious)' }
    };

    const explanation = {
      language: lang,
      verdict,
      title: parsed.title,
      badge: (badgeMap[lang] && badgeMap[lang][verdict]) || badgeMap.en[verdict],
      summary: parsed.summary,
      what_it_means: parsed.what_it_means,
      what_to_do: parsed.what_to_do,
      elderly_advice: parsed.elderly_advice,
      message: parsed.message || parsed.summary,
      detected_points: detectedIndicators.length > 0 ? detectedIndicators : [indicatorText],
      generated_by: `gemini_${lang}`
    };

    if (explanationCache.size < MAX_CACHE_SIZE) {
      explanationCache.set(cacheKey, explanation);
    }

    return explanation;
  } catch (err) {
    const errMsg = err?.message || '';
    const isQuotaError = errMsg.includes('429') || errMsg.includes('RESOURCE_EXHAUSTED') || errMsg.includes('Quota exceeded') || errMsg.includes('rate-limit');
    
    if (isQuotaError) {
      // Engage circuit breaker for 30 minutes to prevent quota hammering
      quotaCooldownUntil = Date.now() + 30 * 60 * 1000;
      console.log(`[URL-Guard Explainer] Gemini API quota limit reached. Cooldown engaged until ${new Date(quotaCooldownUntil).toISOString()}. Serving instant deterministic explanation for ${lang}.`);
    } else {
      console.log(`[URL-Guard Explainer] Seamless fallback to deterministic engine for ${lang}.`);
    }

    const fallback = generateFallbackExplanation({
      verdict,
      score,
      ruleFlags,
      topFactors,
      intelResult,
      language: lang
    });

    if (explanationCache.size < MAX_CACHE_SIZE) {
      explanationCache.set(cacheKey, fallback);
    }

    return fallback;
  }
}
