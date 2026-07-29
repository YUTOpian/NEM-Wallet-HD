/**
 * mnemonic-wallet.js — BIP-39 mnemonic wallet creation & import for NEM Wallet
 * ---------------------------------------------------------------------------
 * Adds two things to the running app, without touching main.js:
 *   1. A "Mnemonic wallet" button (bottom-right) that opens a small dialog to
 *      either GENERATE a new 12/24-word BIP-39 mnemonic and create a wallet
 *      from it, or IMPORT an existing BIP-39 mnemonic into a new wallet.
 *   2. The actual key derivation, done entirely client-side with a
 *      self-contained (dependency-free) implementation of:
 *        - SHA-256 / SHA-512 / HMAC-SHA512 / PBKDF2-HMAC-SHA512 (BIP-39)
 *        - SLIP-0010 derivation for the ed25519 curve (hardened-only),
 *          using NEM's registered SLIP-44 coin type 43, at path
 *              m / 44' / 43' / <account>' / 0' / 0'
 *          which is the same scheme used by NEM-compatible hardware
 *          wallets / other multi-currency wallets, so a mnemonic generated
 *          here can be restored elsewhere (and vice-versa).
 *
 * The derived 32-byte key is handed to the app's own, already-audited
 * `WalletBuilder.createPrivateKeyWallet(...)` pipeline (the exact same
 * function used by the existing "import private key" flow), so the
 * resulting wallet is encrypted/stored/decrypted with the exact same code
 * path as every other wallet in the app. This file never re-implements
 * wallet encryption/decryption.
 *
 * IMPORTANT ABOUT NEM's ECOSYSTEM:
 * The original NEM (NIS1) wallet standard has no *official* mnemonic spec.
 * This implementation uses BIP-39 (mnemonic -> seed) + SLIP-0010 (seed ->
 * ed25519 key), coin type 43 (NEM's registered SLIP-44 number). This is a
 * commonly used, standard, well-documented combination (the same one used
 * for HD derivation of NEM keys on hardware wallets), but please note it is
 * a convention, not something enforced by the NEM protocol itself — as long
 * as this script (or another implementation using the same standard) is used
 * for both creation and recovery, the wallet will always be derivable from
 * its mnemonic.
 *
 * Fails safe: any unexpected error anywhere in this file only disables the
 * mnemonic-wallet button; it never breaks the rest of the app.
 */
(function () {
  'use strict';

  //////////////////////////////////////////////////////////////////////////
  // BIP-39 English wordlist (2048 words, from bitcoin/bips, sorted A-Z)
  //////////////////////////////////////////////////////////////////////////
  var WORDLIST = [
"abandon","ability","able","about","above","absent","absorb","abstract","absurd","abuse","access","accident",
"account","accuse","achieve","acid","acoustic","acquire","across","act","action","actor","actress","actual",
"adapt","add","addict","address","adjust","admit","adult","advance","advice","aerobic","affair","afford",
"afraid","again","age","agent","agree","ahead","aim","air","airport","aisle","alarm","album",
"alcohol","alert","alien","all","alley","allow","almost","alone","alpha","already","also","alter",
"always","amateur","amazing","among","amount","amused","analyst","anchor","ancient","anger","angle","angry",
"animal","ankle","announce","annual","another","answer","antenna","antique","anxiety","any","apart","apology",
"appear","apple","approve","april","arch","arctic","area","arena","argue","arm","armed","armor",
"army","around","arrange","arrest","arrive","arrow","art","artefact","artist","artwork","ask","aspect",
"assault","asset","assist","assume","asthma","athlete","atom","attack","attend","attitude","attract","auction",
"audit","august","aunt","author","auto","autumn","average","avocado","avoid","awake","aware","away",
"awesome","awful","awkward","axis","baby","bachelor","bacon","badge","bag","balance","balcony","ball",
"bamboo","banana","banner","bar","barely","bargain","barrel","base","basic","basket","battle","beach",
"bean","beauty","because","become","beef","before","begin","behave","behind","believe","below","belt",
"bench","benefit","best","betray","better","between","beyond","bicycle","bid","bike","bind","biology",
"bird","birth","bitter","black","blade","blame","blanket","blast","bleak","bless","blind","blood",
"blossom","blouse","blue","blur","blush","board","boat","body","boil","bomb","bone","bonus",
"book","boost","border","boring","borrow","boss","bottom","bounce","box","boy","bracket","brain",
"brand","brass","brave","bread","breeze","brick","bridge","brief","bright","bring","brisk","broccoli",
"broken","bronze","broom","brother","brown","brush","bubble","buddy","budget","buffalo","build","bulb",
"bulk","bullet","bundle","bunker","burden","burger","burst","bus","business","busy","butter","buyer",
"buzz","cabbage","cabin","cable","cactus","cage","cake","call","calm","camera","camp","can",
"canal","cancel","candy","cannon","canoe","canvas","canyon","capable","capital","captain","car","carbon",
"card","cargo","carpet","carry","cart","case","cash","casino","castle","casual","cat","catalog",
"catch","category","cattle","caught","cause","caution","cave","ceiling","celery","cement","census","century",
"cereal","certain","chair","chalk","champion","change","chaos","chapter","charge","chase","chat","cheap",
"check","cheese","chef","cherry","chest","chicken","chief","child","chimney","choice","choose","chronic",
"chuckle","chunk","churn","cigar","cinnamon","circle","citizen","city","civil","claim","clap","clarify",
"claw","clay","clean","clerk","clever","click","client","cliff","climb","clinic","clip","clock",
"clog","close","cloth","cloud","clown","club","clump","cluster","clutch","coach","coast","coconut",
"code","coffee","coil","coin","collect","color","column","combine","come","comfort","comic","common",
"company","concert","conduct","confirm","congress","connect","consider","control","convince","cook","cool","copper",
"copy","coral","core","corn","correct","cost","cotton","couch","country","couple","course","cousin",
"cover","coyote","crack","cradle","craft","cram","crane","crash","crater","crawl","crazy","cream",
"credit","creek","crew","cricket","crime","crisp","critic","crop","cross","crouch","crowd","crucial",
"cruel","cruise","crumble","crunch","crush","cry","crystal","cube","culture","cup","cupboard","curious",
"current","curtain","curve","cushion","custom","cute","cycle","dad","damage","damp","dance","danger",
"daring","dash","daughter","dawn","day","deal","debate","debris","decade","december","decide","decline",
"decorate","decrease","deer","defense","define","defy","degree","delay","deliver","demand","demise","denial",
"dentist","deny","depart","depend","deposit","depth","deputy","derive","describe","desert","design","desk",
"despair","destroy","detail","detect","develop","device","devote","diagram","dial","diamond","diary","dice",
"diesel","diet","differ","digital","dignity","dilemma","dinner","dinosaur","direct","dirt","disagree","discover",
"disease","dish","dismiss","disorder","display","distance","divert","divide","divorce","dizzy","doctor","document",
"dog","doll","dolphin","domain","donate","donkey","donor","door","dose","double","dove","draft",
"dragon","drama","drastic","draw","dream","dress","drift","drill","drink","drip","drive","drop",
"drum","dry","duck","dumb","dune","during","dust","dutch","duty","dwarf","dynamic","eager",
"eagle","early","earn","earth","easily","east","easy","echo","ecology","economy","edge","edit",
"educate","effort","egg","eight","either","elbow","elder","electric","elegant","element","elephant","elevator",
"elite","else","embark","embody","embrace","emerge","emotion","employ","empower","empty","enable","enact",
"end","endless","endorse","enemy","energy","enforce","engage","engine","enhance","enjoy","enlist","enough",
"enrich","enroll","ensure","enter","entire","entry","envelope","episode","equal","equip","era","erase",
"erode","erosion","error","erupt","escape","essay","essence","estate","eternal","ethics","evidence","evil",
"evoke","evolve","exact","example","excess","exchange","excite","exclude","excuse","execute","exercise","exhaust",
"exhibit","exile","exist","exit","exotic","expand","expect","expire","explain","expose","express","extend",
"extra","eye","eyebrow","fabric","face","faculty","fade","faint","faith","fall","false","fame",
"family","famous","fan","fancy","fantasy","farm","fashion","fat","fatal","father","fatigue","fault",
"favorite","feature","february","federal","fee","feed","feel","female","fence","festival","fetch","fever",
"few","fiber","fiction","field","figure","file","film","filter","final","find","fine","finger",
"finish","fire","firm","first","fiscal","fish","fit","fitness","fix","flag","flame","flash",
"flat","flavor","flee","flight","flip","float","flock","floor","flower","fluid","flush","fly",
"foam","focus","fog","foil","fold","follow","food","foot","force","forest","forget","fork",
"fortune","forum","forward","fossil","foster","found","fox","fragile","frame","frequent","fresh","friend",
"fringe","frog","front","frost","frown","frozen","fruit","fuel","fun","funny","furnace","fury",
"future","gadget","gain","galaxy","gallery","game","gap","garage","garbage","garden","garlic","garment",
"gas","gasp","gate","gather","gauge","gaze","general","genius","genre","gentle","genuine","gesture",
"ghost","giant","gift","giggle","ginger","giraffe","girl","give","glad","glance","glare","glass",
"glide","glimpse","globe","gloom","glory","glove","glow","glue","goat","goddess","gold","good",
"goose","gorilla","gospel","gossip","govern","gown","grab","grace","grain","grant","grape","grass",
"gravity","great","green","grid","grief","grit","grocery","group","grow","grunt","guard","guess",
"guide","guilt","guitar","gun","gym","habit","hair","half","hammer","hamster","hand","happy",
"harbor","hard","harsh","harvest","hat","have","hawk","hazard","head","health","heart","heavy",
"hedgehog","height","hello","helmet","help","hen","hero","hidden","high","hill","hint","hip",
"hire","history","hobby","hockey","hold","hole","holiday","hollow","home","honey","hood","hope",
"horn","horror","horse","hospital","host","hotel","hour","hover","hub","huge","human","humble",
"humor","hundred","hungry","hunt","hurdle","hurry","hurt","husband","hybrid","ice","icon","idea",
"identify","idle","ignore","ill","illegal","illness","image","imitate","immense","immune","impact","impose",
"improve","impulse","inch","include","income","increase","index","indicate","indoor","industry","infant","inflict",
"inform","inhale","inherit","initial","inject","injury","inmate","inner","innocent","input","inquiry","insane",
"insect","inside","inspire","install","intact","interest","into","invest","invite","involve","iron","island",
"isolate","issue","item","ivory","jacket","jaguar","jar","jazz","jealous","jeans","jelly","jewel",
"job","join","joke","journey","joy","judge","juice","jump","jungle","junior","junk","just",
"kangaroo","keen","keep","ketchup","key","kick","kid","kidney","kind","kingdom","kiss","kit",
"kitchen","kite","kitten","kiwi","knee","knife","knock","know","lab","label","labor","ladder",
"lady","lake","lamp","language","laptop","large","later","latin","laugh","laundry","lava","law",
"lawn","lawsuit","layer","lazy","leader","leaf","learn","leave","lecture","left","leg","legal",
"legend","leisure","lemon","lend","length","lens","leopard","lesson","letter","level","liar","liberty",
"library","license","life","lift","light","like","limb","limit","link","lion","liquid","list",
"little","live","lizard","load","loan","lobster","local","lock","logic","lonely","long","loop",
"lottery","loud","lounge","love","loyal","lucky","luggage","lumber","lunar","lunch","luxury","lyrics",
"machine","mad","magic","magnet","maid","mail","main","major","make","mammal","man","manage",
"mandate","mango","mansion","manual","maple","marble","march","margin","marine","market","marriage","mask",
"mass","master","match","material","math","matrix","matter","maximum","maze","meadow","mean","measure",
"meat","mechanic","medal","media","melody","melt","member","memory","mention","menu","mercy","merge",
"merit","merry","mesh","message","metal","method","middle","midnight","milk","million","mimic","mind",
"minimum","minor","minute","miracle","mirror","misery","miss","mistake","mix","mixed","mixture","mobile",
"model","modify","mom","moment","monitor","monkey","monster","month","moon","moral","more","morning",
"mosquito","mother","motion","motor","mountain","mouse","move","movie","much","muffin","mule","multiply",
"muscle","museum","mushroom","music","must","mutual","myself","mystery","myth","naive","name","napkin",
"narrow","nasty","nation","nature","near","neck","need","negative","neglect","neither","nephew","nerve",
"nest","net","network","neutral","never","news","next","nice","night","noble","noise","nominee",
"noodle","normal","north","nose","notable","note","nothing","notice","novel","now","nuclear","number",
"nurse","nut","oak","obey","object","oblige","obscure","observe","obtain","obvious","occur","ocean",
"october","odor","off","offer","office","often","oil","okay","old","olive","olympic","omit",
"once","one","onion","online","only","open","opera","opinion","oppose","option","orange","orbit",
"orchard","order","ordinary","organ","orient","original","orphan","ostrich","other","outdoor","outer","output",
"outside","oval","oven","over","own","owner","oxygen","oyster","ozone","pact","paddle","page",
"pair","palace","palm","panda","panel","panic","panther","paper","parade","parent","park","parrot",
"party","pass","patch","path","patient","patrol","pattern","pause","pave","payment","peace","peanut",
"pear","peasant","pelican","pen","penalty","pencil","people","pepper","perfect","permit","person","pet",
"phone","photo","phrase","physical","piano","picnic","picture","piece","pig","pigeon","pill","pilot",
"pink","pioneer","pipe","pistol","pitch","pizza","place","planet","plastic","plate","play","please",
"pledge","pluck","plug","plunge","poem","poet","point","polar","pole","police","pond","pony",
"pool","popular","portion","position","possible","post","potato","pottery","poverty","powder","power","practice",
"praise","predict","prefer","prepare","present","pretty","prevent","price","pride","primary","print","priority",
"prison","private","prize","problem","process","produce","profit","program","project","promote","proof","property",
"prosper","protect","proud","provide","public","pudding","pull","pulp","pulse","pumpkin","punch","pupil",
"puppy","purchase","purity","purpose","purse","push","put","puzzle","pyramid","quality","quantum","quarter",
"question","quick","quit","quiz","quote","rabbit","raccoon","race","rack","radar","radio","rail",
"rain","raise","rally","ramp","ranch","random","range","rapid","rare","rate","rather","raven",
"raw","razor","ready","real","reason","rebel","rebuild","recall","receive","recipe","record","recycle",
"reduce","reflect","reform","refuse","region","regret","regular","reject","relax","release","relief","rely",
"remain","remember","remind","remove","render","renew","rent","reopen","repair","repeat","replace","report",
"require","rescue","resemble","resist","resource","response","result","retire","retreat","return","reunion","reveal",
"review","reward","rhythm","rib","ribbon","rice","rich","ride","ridge","rifle","right","rigid",
"ring","riot","ripple","risk","ritual","rival","river","road","roast","robot","robust","rocket",
"romance","roof","rookie","room","rose","rotate","rough","round","route","royal","rubber","rude",
"rug","rule","run","runway","rural","sad","saddle","sadness","safe","sail","salad","salmon",
"salon","salt","salute","same","sample","sand","satisfy","satoshi","sauce","sausage","save","say",
"scale","scan","scare","scatter","scene","scheme","school","science","scissors","scorpion","scout","scrap",
"screen","script","scrub","sea","search","season","seat","second","secret","section","security","seed",
"seek","segment","select","sell","seminar","senior","sense","sentence","series","service","session","settle",
"setup","seven","shadow","shaft","shallow","share","shed","shell","sheriff","shield","shift","shine",
"ship","shiver","shock","shoe","shoot","shop","short","shoulder","shove","shrimp","shrug","shuffle",
"shy","sibling","sick","side","siege","sight","sign","silent","silk","silly","silver","similar",
"simple","since","sing","siren","sister","situate","six","size","skate","sketch","ski","skill",
"skin","skirt","skull","slab","slam","sleep","slender","slice","slide","slight","slim","slogan",
"slot","slow","slush","small","smart","smile","smoke","smooth","snack","snake","snap","sniff",
"snow","soap","soccer","social","sock","soda","soft","solar","soldier","solid","solution","solve",
"someone","song","soon","sorry","sort","soul","sound","soup","source","south","space","spare",
"spatial","spawn","speak","special","speed","spell","spend","sphere","spice","spider","spike","spin",
"spirit","split","spoil","sponsor","spoon","sport","spot","spray","spread","spring","spy","square",
"squeeze","squirrel","stable","stadium","staff","stage","stairs","stamp","stand","start","state","stay",
"steak","steel","stem","step","stereo","stick","still","sting","stock","stomach","stone","stool",
"story","stove","strategy","street","strike","strong","struggle","student","stuff","stumble","style","subject",
"submit","subway","success","such","sudden","suffer","sugar","suggest","suit","summer","sun","sunny",
"sunset","super","supply","supreme","sure","surface","surge","surprise","surround","survey","suspect","sustain",
"swallow","swamp","swap","swarm","swear","sweet","swift","swim","swing","switch","sword","symbol",
"symptom","syrup","system","table","tackle","tag","tail","talent","talk","tank","tape","target",
"task","taste","tattoo","taxi","teach","team","tell","ten","tenant","tennis","tent","term",
"test","text","thank","that","theme","then","theory","there","they","thing","this","thought",
"three","thrive","throw","thumb","thunder","ticket","tide","tiger","tilt","timber","time","tiny",
"tip","tired","tissue","title","toast","tobacco","today","toddler","toe","together","toilet","token",
"tomato","tomorrow","tone","tongue","tonight","tool","tooth","top","topic","topple","torch","tornado",
"tortoise","toss","total","tourist","toward","tower","town","toy","track","trade","traffic","tragic",
"train","transfer","trap","trash","travel","tray","treat","tree","trend","trial","tribe","trick",
"trigger","trim","trip","trophy","trouble","truck","true","truly","trumpet","trust","truth","try",
"tube","tuition","tumble","tuna","tunnel","turkey","turn","turtle","twelve","twenty","twice","twin",
"twist","two","type","typical","ugly","umbrella","unable","unaware","uncle","uncover","under","undo",
"unfair","unfold","unhappy","uniform","unique","unit","universe","unknown","unlock","until","unusual","unveil",
"update","upgrade","uphold","upon","upper","upset","urban","urge","usage","use","used","useful",
"useless","usual","utility","vacant","vacuum","vague","valid","valley","valve","van","vanish","vapor",
"various","vast","vault","vehicle","velvet","vendor","venture","venue","verb","verify","version","very",
"vessel","veteran","viable","vibrant","vicious","victory","video","view","village","vintage","violin","virtual",
"virus","visa","visit","visual","vital","vivid","vocal","voice","void","volcano","volume","vote",
"voyage","wage","wagon","wait","walk","wall","walnut","want","warfare","warm","warrior","wash",
"wasp","waste","water","wave","way","wealth","weapon","wear","weasel","weather","web","wedding",
"weekend","weird","welcome","west","wet","whale","what","wheat","wheel","when","where","whip",
"whisper","wide","width","wife","wild","will","win","window","wine","wing","wink","winner",
"winter","wire","wisdom","wise","wish","witness","wolf","woman","wonder","wood","wool","word",
"work","world","worry","worth","wrap","wreck","wrestle","wrist","write","wrong","yard","year",
"yellow","you","young","youth","zebra","zero","zone","zoo"
  ];

  //////////////////////////////////////////////////////////////////////////
  // SHA-256 (pure JS, used only for the BIP-39 checksum)
  //////////////////////////////////////////////////////////////////////////
  var K256 = [
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
  ];

  function rotr32(x, n) { return (x >>> n) | (x << (32 - n)); }

  function sha256(message) {
    var H = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
    var l = message.length;
    var withOne = l + 1;
    var padLen = ((withOne + 8) % 64 === 0) ? 0 : 64 - ((withOne + 8) % 64);
    var totalLen = withOne + padLen + 8;
    var buf = new Uint8Array(totalLen);
    buf.set(message, 0);
    buf[l] = 0x80;
    var view = new DataView(buf.buffer);
    var bitLen = l * 8;
    view.setUint32(totalLen - 4, bitLen >>> 0, false);
    view.setUint32(totalLen - 8, Math.floor(l / 0x20000000), false);

    var W = new Array(64);
    for (var offset = 0; offset < totalLen; offset += 64) {
      for (var t = 0; t < 16; t++) W[t] = view.getUint32(offset + t * 4, false);
      for (var t2 = 16; t2 < 64; t2++) {
        var w15 = W[t2 - 15], w2 = W[t2 - 2];
        var s0 = (rotr32(w15, 7) ^ rotr32(w15, 18) ^ (w15 >>> 3));
        var s1 = (rotr32(w2, 17) ^ rotr32(w2, 19) ^ (w2 >>> 10));
        W[t2] = (W[t2 - 16] + s0 + W[t2 - 7] + s1) >>> 0;
      }
      var a = H[0], b = H[1], c = H[2], d = H[3], e = H[4], f = H[5], g = H[6], h = H[7];
      for (var t3 = 0; t3 < 64; t3++) {
        var S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
        var ch = (e & f) ^ (~e & g);
        var temp1 = (h + S1 + ch + K256[t3] + W[t3]) >>> 0;
        var S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
        var maj = (a & b) ^ (a & c) ^ (b & c);
        var temp2 = (S0 + maj) >>> 0;
        h = g; g = f; f = e; e = (d + temp1) >>> 0; d = c; c = b; b = a; a = (temp1 + temp2) >>> 0;
      }
      H[0]=(H[0]+a)>>>0; H[1]=(H[1]+b)>>>0; H[2]=(H[2]+c)>>>0; H[3]=(H[3]+d)>>>0;
      H[4]=(H[4]+e)>>>0; H[5]=(H[5]+f)>>>0; H[6]=(H[6]+g)>>>0; H[7]=(H[7]+h)>>>0;
    }
    var out = new Uint8Array(32);
    var ov = new DataView(out.buffer);
    for (var i = 0; i < 8; i++) ov.setUint32(i * 4, H[i], false);
    return out;
  }

  //////////////////////////////////////////////////////////////////////////
  // SHA-512 / HMAC-SHA512 / PBKDF2-HMAC-SHA512 (pure JS, no BigInt needed;
  // 64-bit words are represented as {hi, lo} 32-bit pairs)
  //////////////////////////////////////////////////////////////////////////
  var K512 = [
    [0x428a2f98,0xd728ae22],[0x71374491,0x23ef65cd],[0xb5c0fbcf,0xec4d3b2f],[0xe9b5dba5,0x8189dbbc],
    [0x3956c25b,0xf348b538],[0x59f111f1,0xb605d019],[0x923f82a4,0xaf194f9b],[0xab1c5ed5,0xda6d8118],
    [0xd807aa98,0xa3030242],[0x12835b01,0x45706fbe],[0x243185be,0x4ee4b28c],[0x550c7dc3,0xd5ffb4e2],
    [0x72be5d74,0xf27b896f],[0x80deb1fe,0x3b1696b1],[0x9bdc06a7,0x25c71235],[0xc19bf174,0xcf692694],
    [0xe49b69c1,0x9ef14ad2],[0xefbe4786,0x384f25e3],[0x0fc19dc6,0x8b8cd5b5],[0x240ca1cc,0x77ac9c65],
    [0x2de92c6f,0x592b0275],[0x4a7484aa,0x6ea6e483],[0x5cb0a9dc,0xbd41fbd4],[0x76f988da,0x831153b5],
    [0x983e5152,0xee66dfab],[0xa831c66d,0x2db43210],[0xb00327c8,0x98fb213f],[0xbf597fc7,0xbeef0ee4],
    [0xc6e00bf3,0x3da88fc2],[0xd5a79147,0x930aa725],[0x06ca6351,0xe003826f],[0x14292967,0x0a0e6e70],
    [0x27b70a85,0x46d22ffc],[0x2e1b2138,0x5c26c926],[0x4d2c6dfc,0x5ac42aed],[0x53380d13,0x9d95b3df],
    [0x650a7354,0x8baf63de],[0x766a0abb,0x3c77b2a8],[0x81c2c92e,0x47edaee6],[0x92722c85,0x1482353b],
    [0xa2bfe8a1,0x4cf10364],[0xa81a664b,0xbc423001],[0xc24b8b70,0xd0f89791],[0xc76c51a3,0x0654be30],
    [0xd192e819,0xd6ef5218],[0xd6990624,0x5565a910],[0xf40e3585,0x5771202a],[0x106aa070,0x32bbd1b8],
    [0x19a4c116,0xb8d2d0c8],[0x1e376c08,0x5141ab53],[0x2748774c,0xdf8eeb99],[0x34b0bcb5,0xe19b48a8],
    [0x391c0cb3,0xc5c95a63],[0x4ed8aa4a,0xe3418acb],[0x5b9cca4f,0x7763e373],[0x682e6ff3,0xd6b2b8a3],
    [0x748f82ee,0x5defb2fc],[0x78a5636f,0x43172f60],[0x84c87814,0xa1f0ab72],[0x8cc70208,0x1a6439ec],
    [0x90befffa,0x23631e28],[0xa4506ceb,0xde82bde9],[0xbef9a3f7,0xb2c67915],[0xc67178f2,0xe372532b],
    [0xca273ece,0xea26619c],[0xd186b8c7,0x21c0c207],[0xeada7dd6,0xcde0eb1e],[0xf57d4f7f,0xee6ed178],
    [0x06f067aa,0x72176fba],[0x0a637dc5,0xa2c898a6],[0x113f9804,0xbef90dae],[0x1b710b35,0x131c471b],
    [0x28db77f5,0x23047d84],[0x32caab7b,0x40c72493],[0x3c9ebe0a,0x15c9bebc],[0x431d67c4,0x9c100d4c],
    [0x4cc5d4be,0xcb3e42b6],[0x597f299c,0xfc657e2a],[0x5fcb6fab,0x3ad6faec],[0x6c44198c,0x4a475817]
  ];

  function u64(hi, lo) { return { hi: hi >>> 0, lo: lo >>> 0 }; }
  function add64(a, b) {
    var lo = (a.lo + b.lo) >>> 0;
    var carry = (lo < (a.lo >>> 0)) ? 1 : 0;
    var hi = (a.hi + b.hi + carry) >>> 0;
    return u64(hi, lo);
  }
  function add64_4(a,b,c,d){ return add64(add64(a,b), add64(c,d)); }
  function add64_5(a,b,c,d,e){ return add64(add64_4(a,b,c,d), e); }
  function rotr64(x, n) {
    if (n === 0) return u64(x.hi, x.lo);
    if (n < 32) {
      var lo = ((x.lo >>> n) | (x.hi << (32 - n))) >>> 0;
      var hi = ((x.hi >>> n) | (x.lo << (32 - n))) >>> 0;
      return u64(hi, lo);
    } else if (n === 32) {
      return u64(x.lo, x.hi);
    } else {
      var n2 = n - 32;
      var lo2 = ((x.hi >>> n2) | (x.lo << (32 - n2))) >>> 0;
      var hi2 = ((x.lo >>> n2) | (x.hi << (32 - n2))) >>> 0;
      return u64(hi2, lo2);
    }
  }
  function shr64(x, n) {
    if (n === 0) return u64(x.hi, x.lo);
    if (n < 32) {
      var lo = ((x.lo >>> n) | (x.hi << (32 - n))) >>> 0;
      var hi = (x.hi >>> n) >>> 0;
      return u64(hi, lo);
    } else {
      var lo2 = (x.hi >>> (n - 32)) >>> 0;
      return u64(0, lo2);
    }
  }
  function xor64(a,b){ return u64((a.hi ^ b.hi) >>> 0, (a.lo ^ b.lo) >>> 0); }
  function and64(a,b){ return u64((a.hi & b.hi) >>> 0, (a.lo & b.lo) >>> 0); }
  function not64(a){ return u64((~a.hi) >>> 0, (~a.lo) >>> 0); }

  function sha512(message) {
    var H = [
      u64(0x6a09e667,0xf3bcc908), u64(0xbb67ae85,0x84caa73b),
      u64(0x3c6ef372,0xfe94f82b), u64(0xa54ff53a,0x5f1d36f1),
      u64(0x510e527f,0xade682d1), u64(0x9b05688c,0x2b3e6c1f),
      u64(0x1f83d9ab,0xfb41bd6b), u64(0x5be0cd19,0x137e2179)
    ];
    var l = message.length;
    var withOne = l + 1;
    var padLen = ((withOne + 16) % 128 === 0) ? 0 : 128 - ((withOne + 16) % 128);
    var totalLen = withOne + padLen + 16;
    var buf = new Uint8Array(totalLen);
    buf.set(message, 0);
    buf[l] = 0x80;
    var bitLenLo = (l * 8) >>> 0;
    var bitLenHiPart = Math.floor(l / 0x20000000);
    var view = new DataView(buf.buffer);
    view.setUint32(totalLen - 4, bitLenLo, false);
    view.setUint32(totalLen - 8, bitLenHiPart, false);

    var W = new Array(80);
    for (var offset = 0; offset < totalLen; offset += 128) {
      for (var t = 0; t < 16; t++) {
        var o = offset + t * 8;
        W[t] = u64(view.getUint32(o, false), view.getUint32(o + 4, false));
      }
      for (var t2 = 16; t2 < 80; t2++) {
        var w15 = W[t2-15], w2 = W[t2-2];
        var s0 = xor64(xor64(rotr64(w15,1), rotr64(w15,8)), shr64(w15,7));
        var s1 = xor64(xor64(rotr64(w2,19), rotr64(w2,61)), shr64(w2,6));
        W[t2] = add64_4(W[t2-16], s0, W[t2-7], s1);
      }
      var a=H[0],b=H[1],c=H[2],d=H[3],e=H[4],f=H[5],g=H[6],h=H[7];
      for (var t3 = 0; t3 < 80; t3++) {
        var S1 = xor64(xor64(rotr64(e,14), rotr64(e,18)), rotr64(e,41));
        var ch = xor64(and64(e,f), and64(not64(e), g));
        var temp1 = add64_5(h, S1, ch, u64(K512[t3][0],K512[t3][1]), W[t3]);
        var S0 = xor64(xor64(rotr64(a,28), rotr64(a,34)), rotr64(a,39));
        var maj = xor64(xor64(and64(a,b), and64(a,c)), and64(b,c));
        var temp2 = add64(S0, maj);
        h=g; g=f; f=e; e=add64(d,temp1); d=c; c=b; b=a; a=add64(temp1,temp2);
      }
      H[0]=add64(H[0],a); H[1]=add64(H[1],b); H[2]=add64(H[2],c); H[3]=add64(H[3],d);
      H[4]=add64(H[4],e); H[5]=add64(H[5],f); H[6]=add64(H[6],g); H[7]=add64(H[7],h);
    }
    var out = new Uint8Array(64);
    var ov = new DataView(out.buffer);
    for (var i = 0; i < 8; i++) {
      ov.setUint32(i*8, H[i].hi, false);
      ov.setUint32(i*8+4, H[i].lo, false);
    }
    return out;
  }

  function concatBytes() {
    var total = 0;
    for (var i = 0; i < arguments.length; i++) total += arguments[i].length;
    var out = new Uint8Array(total);
    var off = 0;
    for (var i2 = 0; i2 < arguments.length; i2++) {
      out.set(arguments[i2], off);
      off += arguments[i2].length;
    }
    return out;
  }

  function hmacSha512(key, message) {
    var blockSize = 128;
    if (key.length > blockSize) key = sha512(key);
    if (key.length < blockSize) {
      var k2 = new Uint8Array(blockSize);
      k2.set(key, 0);
      key = k2;
    }
    var oKeyPad = new Uint8Array(blockSize);
    var iKeyPad = new Uint8Array(blockSize);
    for (var i = 0; i < blockSize; i++) {
      oKeyPad[i] = key[i] ^ 0x5c;
      iKeyPad[i] = key[i] ^ 0x36;
    }
    var inner = sha512(concatBytes(iKeyPad, message));
    return sha512(concatBytes(oKeyPad, inner));
  }

  function pbkdf2Sha512(password, salt, iterations, keylen) {
    var hLen = 64;
    var l = Math.ceil(keylen / hLen);
    var out = new Uint8Array(l * hLen);
    for (var i = 1; i <= l; i++) {
      var intBlock = new Uint8Array(4);
      var dv = new DataView(intBlock.buffer);
      dv.setUint32(0, i, false);
      var u = hmacSha512(password, concatBytes(salt, intBlock));
      var t = u.slice();
      for (var c = 1; c < iterations; c++) {
        u = hmacSha512(password, u);
        for (var j = 0; j < hLen; j++) t[j] ^= u[j];
      }
      out.set(t, (i - 1) * hLen);
    }
    return out.slice(0, keylen);
  }

  function bytesToHex(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) {
      s += (bytes[i] < 16 ? '0' : '') + bytes[i].toString(16);
    }
    return s;
  }

  function utf8Bytes(str) {
    return new Uint8Array(new TextEncoder().encode(str));
  }

  function hexToBytes(hex) {
    var out = new Uint8Array(hex.length / 2);
    for (var i = 0; i < out.length; i++) out[i] = parseInt(hex.substr(i * 2, 2), 16);
    return out;
  }

  function randomBytes(n) {
    var b = new Uint8Array(n);
    window.crypto.getRandomValues(b);
    return b;
  }

  //////////////////////////////////////////////////////////////////////////
  // Mnemonic backup storage (encrypted at rest with the wallet password,
  // via the browser's own Web Crypto AES-GCM implementation — this file
  // never re-implements AES itself). Stored separately from `wallets` so
  // it never interferes with anything the rest of the app reads/writes.
  //////////////////////////////////////////////////////////////////////////

  function encryptMnemonicBackup(mnemonic, password) {
    if (!window.crypto || !window.crypto.subtle) return Promise.reject(new Error('Web Crypto not available'));
    var salt = randomBytes(16);
    var iv = randomBytes(12);
    return window.crypto.subtle.importKey('raw', utf8Bytes(password), { name: 'PBKDF2' }, false, ['deriveKey']).then(function (keyMaterial) {
      return window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['encrypt']
      );
    }).then(function (key) {
      return window.crypto.subtle.encrypt({ name: 'AES-GCM', iv: iv }, key, utf8Bytes(mnemonic));
    }).then(function (cipherBuf) {
      return { salt: bytesToHex(salt), iv: bytesToHex(iv), ciphertext: bytesToHex(new Uint8Array(cipherBuf)) };
    });
  }

  function decryptMnemonicBackup(backup, password) {
    if (!window.crypto || !window.crypto.subtle) return Promise.reject(new Error('Web Crypto not available'));
    var salt = hexToBytes(backup.salt);
    var iv = hexToBytes(backup.iv);
    return window.crypto.subtle.importKey('raw', utf8Bytes(password), { name: 'PBKDF2' }, false, ['deriveKey']).then(function (keyMaterial) {
      return window.crypto.subtle.deriveKey(
        { name: 'PBKDF2', salt: salt, iterations: 100000, hash: 'SHA-256' },
        keyMaterial, { name: 'AES-GCM', length: 256 }, false, ['decrypt']
      );
    }).then(function (key) {
      return window.crypto.subtle.decrypt({ name: 'AES-GCM', iv: iv }, key, hexToBytes(backup.ciphertext));
    }).then(function (plainBuf) {
      return new TextDecoder().decode(plainBuf);
    });
    // Wrong password => AES-GCM auth tag check fails => promise rejects.
  }

  function getBackups(injector) {
    var storage = injector.get('$localStorage');
    return storage.mnemonicBackups || {};
  }

  function saveBackup(injector, address, backup) {
    var storage = injector.get('$localStorage');
    var backups = Object.assign({}, storage.mnemonicBackups || {});
    backups[address] = backup;
    storage.mnemonicBackups = backups;
    injector.get('$rootScope').$applyAsync();
  }

  function deleteBackup(injector, address) {
    var storage = injector.get('$localStorage');
    var backups = Object.assign({}, storage.mnemonicBackups || {});
    delete backups[address];
    storage.mnemonicBackups = backups;
    injector.get('$rootScope').$applyAsync();
  }

  //////////////////////////////////////////////////////////////////////////
  // BIP-39
  //////////////////////////////////////////////////////////////////////////

  // strength: 128 (12 words) or 256 (24 words)
  function generateMnemonic(strength) {
    strength = strength || 128;
    var entropy = new Uint8Array(strength / 8);
    if (window.crypto && window.crypto.getRandomValues) {
      window.crypto.getRandomValues(entropy);
    } else {
      throw new Error('No secure random number generator available');
    }
    return entropyToMnemonic(entropy);
  }

  function entropyToMnemonic(entropyBytes) {
    var ENT = entropyBytes.length * 8;
    var CS = ENT / 32;
    var hash = sha256(entropyBytes);

    var bits = '';
    for (var i = 0; i < entropyBytes.length; i++) bits += entropyBytes[i].toString(2).padStart ? entropyBytes[i].toString(2).padStart(8, '0') : padLeft(entropyBytes[i].toString(2), 8);
    var checksumBits = '';
    for (var j = 0; j < hash.length; j++) checksumBits += hash[j].toString(2).padStart ? hash[j].toString(2).padStart(8, '0') : padLeft(hash[j].toString(2), 8);
    bits += checksumBits.slice(0, CS);

    var words = [];
    for (var k = 0; k < bits.length / 11; k++) {
      var idx = parseInt(bits.slice(k * 11, k * 11 + 11), 2);
      words.push(WORDLIST[idx]);
    }
    return words.join(' ');
  }

  function padLeft(s, len) {
    while (s.length < len) s = '0' + s;
    return s;
  }

  // Returns {valid: bool, reason: string}
  function validateMnemonic(mnemonic) {
    if (!mnemonic || typeof mnemonic !== 'string') return { valid: false, reason: 'EMPTY' };
    var words = mnemonic.trim().split(/\s+/);
    if ([12, 15, 18, 21, 24].indexOf(words.length) === -1) {
      return { valid: false, reason: 'WORD_COUNT' };
    }
    var bits = '';
    for (var i = 0; i < words.length; i++) {
      var idx = WORDLIST.indexOf(words[i].toLowerCase());
      if (idx === -1) return { valid: false, reason: 'UNKNOWN_WORD', word: words[i] };
      bits += padLeft(idx.toString(2), 11);
    }
    var dividerIndex = Math.floor(bits.length / 33) * 32;
    var entropyBits = bits.slice(0, dividerIndex);
    var checksumBits = bits.slice(dividerIndex);

    var entropyBytes = new Uint8Array(entropyBits.length / 8);
    for (var b = 0; b < entropyBytes.length; b++) {
      entropyBytes[b] = parseInt(entropyBits.slice(b * 8, b * 8 + 8), 2);
    }
    var hash = sha256(entropyBytes);
    var expectedChecksum = '';
    for (var c = 0; c < hash.length; c++) expectedChecksum += padLeft(hash[c].toString(2), 8);
    expectedChecksum = expectedChecksum.slice(0, checksumBits.length);

    if (expectedChecksum !== checksumBits) return { valid: false, reason: 'CHECKSUM' };
    return { valid: true };
  }

  function mnemonicToSeed(mnemonic, passphrase) {
    passphrase = passphrase || '';
    var mnBytes = utf8Bytes(mnemonic.trim().normalize('NFKD'));
    var saltBytes = utf8Bytes(('mnemonic' + passphrase).normalize('NFKD'));
    return pbkdf2Sha512(mnBytes, saltBytes, 2048, 64);
  }

  //////////////////////////////////////////////////////////////////////////
  // SLIP-0010 (ed25519, hardened-only derivation)
  //////////////////////////////////////////////////////////////////////////

  function ser32(i) {
    var b = new Uint8Array(4);
    b[0] = (i >>> 24) & 0xff;
    b[1] = (i >>> 16) & 0xff;
    b[2] = (i >>> 8) & 0xff;
    b[3] = i & 0xff;
    return b;
  }

  function deriveEd25519Master(seed) {
    var key = utf8Bytes('ed25519 seed');
    var I = hmacSha512(key, seed);
    return { key: I.slice(0, 32), chainCode: I.slice(32, 64) };
  }

  function ckdPrivHardened(kpar, cpar, index) {
    var hardenedIndex = (index >>> 0) | 0x80000000;
    var data = concatBytes(new Uint8Array([0]), kpar, ser32(hardenedIndex));
    var I = hmacSha512(cpar, data);
    return { key: I.slice(0, 32), chainCode: I.slice(32, 64) };
  }

  // path like "m/44'/43'/0'/0'/0'" — every segment must be hardened (').
  function derivePath(seed, path) {
    var segments = path.split('/').slice(1).map(function (s) {
      return parseInt(s.replace("'", ''), 10);
    });
    var node = deriveEd25519Master(seed);
    for (var i = 0; i < segments.length; i++) {
      node = ckdPrivHardened(node.key, node.chainCode, segments[i]);
    }
    return node;
  }

  // NEM's registered SLIP-44 coin type is 43.
  function nemPrivateKeyFromMnemonic(mnemonic, passphrase, accountIndex) {
    accountIndex = accountIndex || 0;
    var seed = mnemonicToSeed(mnemonic, passphrase);
    var node = derivePath(seed, "m/44'/43'/" + accountIndex + "'/0'/0'");
    return bytesToHex(node.key);
  }

  //////////////////////////////////////////////////////////////////////////
  // Small DOM helpers
  //////////////////////////////////////////////////////////////////////////

  function el(tag, styles, attrs) {
    var e = document.createElement(tag);
    if (styles) for (var k in styles) if (styles.hasOwnProperty(k)) e.style[k] = styles[k];
    if (attrs) for (var a in attrs) if (attrs.hasOwnProperty(a)) e.setAttribute(a, attrs[a]);
    return e;
  }

  function formGroup(labelText, inputEl) {
    var wrap = el('div', {}, { 'class': 'form-group' });
    var label = document.createElement('label');
    label.textContent = labelText;
    wrap.appendChild(label);
    wrap.appendChild(inputEl);
    return wrap;
  }

  function textInput(placeholder, type) {
    return el('input', {}, { type: type || 'text', 'class': 'form-control', placeholder: placeholder || '' });
  }

  function showMessage(container, text, isError) {
    var m = container._msgEl;
    if (!m) {
      m = el('p', { marginTop: '10px' });
      container.appendChild(m);
      container._msgEl = m;
    }
    m.textContent = text;
    m.className = isError ? 'bg-danger' : 'bg-success';
  }

  //////////////////////////////////////////////////////////////////////////
  // Wallet creation, shared by every entry point in this file. Reuses the
  // app's own WalletBuilder.createPrivateKeyWallet(...) pipeline (the exact
  // function behind "import private key") so storage / encryption /
  // decryption stay 100% consistent with every other wallet in the app,
  // then logs straight into the new wallet the same way the normal signup
  // flow does.
  //////////////////////////////////////////////////////////////////////////

  function finalizeWallet(injector, opts, onDone, onError) {
    try {
      var WalletBuilder = injector.get('WalletBuilder');
      var AddressBook = injector.get('AddressBook');
      var storage = injector.get('$localStorage');
      var ngToast = injector.get('ngToast');
      var rootScope = injector.get('$rootScope');
      var Login = injector.get('Login');

      WalletBuilder.createPrivateKeyWallet(opts.walletName, opts.password, opts.privateKey, opts.network).then(function (wallet) {
        if (!wallet || typeof wallet !== 'object') { onError('ウォレットを作成できませんでした（入力内容を確認するか、同じ名前のウォレットが既にあります）。'); return; }
        try {
          AddressBook.addAccount(wallet.accounts[0].address);
          storage.wallets = (storage.wallets || []).concat(wallet);
          ngToast.create({ className: 'success', content: 'ニーモニックからウォレットを作成しました。' });

          var common = { password: opts.password, privateKey: '', isHW: false };
          var loggedIn = false;
          try { loggedIn = Login.login(common, wallet); } catch (e3) { loggedIn = false; }

          rootScope.$applyAsync();
          onDone(wallet, loggedIn);
        } catch (e2) {
          onError('ウォレットは作成されましたが保存に失敗しました: ' + e2.message);
        }
      }, function () {
        onError('ウォレットを作成できませんでした（入力内容を確認するか、同じ名前のウォレットが既にあります）。');
      });
    } catch (e) {
      onError('予期しないエラー: ' + e.message);
    }
  }

  //////////////////////////////////////////////////////////////////////////
  // Create / Import panel — a single reusable piece of UI, used inline on
  // the signup page (no floating window, no separate modal).
  //////////////////////////////////////////////////////////////////////////

  var NETWORKS = [
    { id: 104, label: 'メインネット' },
    { id: -104, label: 'テストネット' }
  ];

  function buildAdvancedFields() {
    var wrap = document.createDocumentFragment();
    var toggle = el('a', { display: 'inline-block', marginBottom: '10px', cursor: 'pointer' }, { href: '' });
    toggle.textContent = '詳細オプション（パスフレーズ／アカウント番号）';
    var box = el('div', { display: 'none' });
    var passphraseInput = textInput('追加パスフレーズ（省略可・25番目の単語）');
    box.appendChild(formGroup('パスフレーズ（省略可）', passphraseInput));
    var accountIndexInput = textInput('0');
    accountIndexInput.value = '0';
    box.appendChild(formGroup('アカウント番号', accountIndexInput));
    toggle.addEventListener('click', function (e) {
      e.preventDefault();
      box.style.display = box.style.display === 'none' ? 'block' : 'none';
    });
    wrap.appendChild(toggle);
    wrap.appendChild(box);
    return { frag: wrap, passphraseInput: passphraseInput, accountIndexInput: accountIndexInput };
  }

  function buildCommonFields() {
    var frag = document.createDocumentFragment();
    var nameInput = textInput('例）マイウォレット');
    frag.appendChild(formGroup('ウォレット名', nameInput));
    var passInput = textInput('40文字以上を推奨', 'password');
    frag.appendChild(formGroup('パスワード', passInput));
    var passConfirm = textInput('パスワード（確認）', 'password');
    frag.appendChild(formGroup('パスワード（確認）', passConfirm));
    var networkSelect = el('select', {}, { 'class': 'form-control' });
    NETWORKS.forEach(function (n) {
      var opt = el('option', {}, { value: String(n.id) });
      opt.textContent = n.label;
      networkSelect.appendChild(opt);
    });
    frag.appendChild(formGroup('ネットワーク', networkSelect));
    var adv = buildAdvancedFields();
    frag.appendChild(adv.frag);
    return {
      frag: frag, nameInput: nameInput, passInput: passInput, passConfirm: passConfirm,
      networkSelect: networkSelect, passphraseInput: adv.passphraseInput, accountIndexInput: adv.accountIndexInput
    };
  }

  function validateCommon(fields, msgContainer) {
    if (!fields.nameInput.value.trim()) { showMessage(msgContainer, 'ウォレット名を入力してください。', true); return null; }
    if (!fields.passInput.value || fields.passInput.value.length < 8) { showMessage(msgContainer, 'パスワードは8文字以上にしてください。', true); return null; }
    if (fields.passInput.value !== fields.passConfirm.value) { showMessage(msgContainer, 'パスワードが一致しません。', true); return null; }
    var accountIndex = parseInt(fields.accountIndexInput.value, 10);
    if (isNaN(accountIndex) || accountIndex < 0) accountIndex = 0;
    return {
      walletName: fields.nameInput.value.trim(), password: fields.passInput.value,
      network: parseInt(fields.networkSelect.value, 10), passphrase: fields.passphraseInput.value || '',
      accountIndex: accountIndex
    };
  }

  function buildCreatePanel(injector, onDone) {
    var pane = el('div', {}, { 'class': 'form-group' });

    var strengthRow = el('div', { display: 'flex', gap: '8px', marginBottom: '10px' });
    var btn12 = el('button', { flex: '1' }, { type: 'button', 'class': 'btn btn-primary' });
    btn12.textContent = '12語';
    var btn24 = el('button', { flex: '1' }, { type: 'button', 'class': 'btn btn-default' });
    btn24.textContent = '24語';
    strengthRow.appendChild(btn12); strengthRow.appendChild(btn24);
    pane.appendChild(strengthRow);

    var mnemonicBox = el('p', { fontFamily: 'monospace', wordBreak: 'break-word', filter: 'blur(4px)' }, { 'class': 'bg-info' });
    var currentMnemonic = generateMnemonic(128);
    mnemonicBox.textContent = currentMnemonic;
    pane.appendChild(mnemonicBox);

    var revealed = false;
    var actionsRow = el('div', { display: 'flex', gap: '8px', marginBottom: '10px' });
    var revealBtn = el('button', { flex: '1' }, { type: 'button', 'class': 'btn btn-default' });
    revealBtn.textContent = '表示する';
    var copyBtn = el('button', { flex: '1' }, { type: 'button', 'class': 'btn btn-default' });
    copyBtn.textContent = 'コピー';
    function setRevealed(v) {
      revealed = v;
      mnemonicBox.style.filter = revealed ? 'none' : 'blur(4px)';
      revealBtn.textContent = revealed ? '隠す' : '表示する';
    }
    revealBtn.addEventListener('click', function () { setRevealed(!revealed); });
    copyBtn.addEventListener('click', function () {
      setRevealed(true);
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(currentMnemonic);
        copyBtn.textContent = 'コピーしました';
        setTimeout(function () { copyBtn.textContent = 'コピー'; }, 1500);
      } catch (e) { /* clipboard unavailable: words are already shown for manual copy */ }
    });
    actionsRow.appendChild(revealBtn); actionsRow.appendChild(copyBtn);
    pane.appendChild(actionsRow);

    var warn = el('p', {}, { 'class': 'bg-warning' });
    warn.textContent = 'この単語列を順番通りに書き留め、オフラインの安全な場所に保管してください。このフレーズを知る人は誰でも資金を送金できます。';
    pane.appendChild(warn);

    function regen(strength) {
      currentMnemonic = generateMnemonic(strength);
      mnemonicBox.textContent = currentMnemonic;
      setRevealed(false);
      setBackupChecked(false);
    }
    btn12.addEventListener('click', function () { btn12.className = 'btn btn-primary'; btn24.className = 'btn btn-default'; regen(128); });
    btn24.addEventListener('click', function () { btn24.className = 'btn btn-primary'; btn12.className = 'btn btn-default'; regen(256); });

    var refreshLink = el('a', { display: 'inline-block', marginBottom: '10px', cursor: 'pointer' }, { href: '' });
    refreshLink.textContent = '別のフレーズを生成する';
    refreshLink.addEventListener('click', function (e) { e.preventDefault(); regen(currentMnemonic.split(' ').length === 12 ? 128 : 256); });
    pane.appendChild(refreshLink);

    var backupChecked = false;
    var backupRow = el('div', {
      display: 'flex', alignItems: 'flex-start', gap: '10px', cursor: 'pointer', padding: '10px',
      borderRadius: '4px', border: '1px solid #d43f3a', marginBottom: '14px'
    });
    var backupBox = el('div', {
      width: '20px', height: '20px', minWidth: '20px', borderRadius: '3px', border: '2px solid #d43f3a',
      display: 'flex', alignItems: 'center', justifyContent: 'center', marginTop: '1px'
    });
    var backupText = document.createElement('span');
    backupText.textContent = 'このニーモニックフレーズを書き留め、安全に保管しました。';
    backupRow.appendChild(backupBox); backupRow.appendChild(backupText);
    pane.appendChild(backupRow);
    var backupCheck = { checked: false };
    function setBackupChecked(v) {
      backupChecked = v; backupCheck.checked = v;
      backupBox.style.background = v ? '#3c763d' : 'transparent';
      backupBox.style.borderColor = v ? '#3c763d' : '#d43f3a';
      backupBox.textContent = v ? '\u2713' : '';
      backupRow.style.borderColor = v ? '#3c763d' : '#d43f3a';
    }
    backupRow.addEventListener('click', function () { setBackupChecked(!backupChecked); });

    var fields = buildCommonFields();
    pane.appendChild(fields.frag);

    var submitBtn = el('button', { width: '100%' }, { type: 'button', 'class': 'btn btn-primary' });
    submitBtn.textContent = 'ウォレットを作成';
    pane.appendChild(submitBtn);

    submitBtn.addEventListener('click', function () {
      if (!backupCheck.checked) { showMessage(pane, 'ニーモニックフレーズをバックアップしたことを確認してください。', true); return; }
      var common = validateCommon(fields, pane);
      if (!common) return;
      submitBtn.disabled = true;
      submitBtn.textContent = '作成中...';
      try {
        var privateKey = nemPrivateKeyFromMnemonic(currentMnemonic, common.passphrase, common.accountIndex);
        finalizeWallet(injector, {
          walletName: common.walletName, password: common.password, network: common.network, privateKey: privateKey
        }, function (wallet, loggedIn) {
          submitBtn.textContent = '完了';
          encryptMnemonicBackup(currentMnemonic, common.password).then(function (backup) {
            saveBackup(injector, wallet.accounts[0].address, backup);
          }).catch(function () { /* backup storage is best-effort */ });
          showMessage(pane, loggedIn ? 'ウォレット「' + common.walletName + '」を作成しました。ダッシュボードに移動します...' : 'ウォレットは作成されましたが自動的に開けませんでした。ログイン画面から選択してください。', !loggedIn);
          if (onDone) onDone(wallet, loggedIn);
        }, function (msg) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'ウォレットを作成';
          showMessage(pane, msg, true);
        });
      } catch (e) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'ウォレットを作成';
        showMessage(pane, 'このニーモニックから鍵を導出できませんでした: ' + e.message, true);
      }
    });

    return pane;
  }

  function buildImportPanel(injector, onDone) {
    var pane = el('div', {}, { 'class': 'form-group' });

    var mnemonicArea = el('textarea', { fontFamily: 'monospace', minHeight: '70px' }, { 'class': 'form-control', placeholder: '12語または24語のニーモニックフレーズをスペース区切りで入力してください' });
    pane.appendChild(formGroup('ニーモニックフレーズ', mnemonicArea));

    var validityMsg = el('p', { fontSize: '12px' });
    pane.appendChild(validityMsg);

    mnemonicArea.addEventListener('input', function () {
      var v = validateMnemonic(mnemonicArea.value);
      if (!mnemonicArea.value.trim()) { validityMsg.textContent = ''; return; }
      if (v.valid) {
        validityMsg.textContent = '有効なニーモニックフレーズです。';
        validityMsg.style.color = '#3c763d';
      } else {
        var reasons = {
          WORD_COUNT: '単語数は12, 15, 18, 21, 24のいずれかである必要があります。',
          UNKNOWN_WORD: '認識できない単語です: ' + (v.word || ''),
          CHECKSUM: 'チェックサムが一致しません。単語と順番を確認してください。',
          EMPTY: 'ニーモニックフレーズを入力してください。'
        };
        validityMsg.textContent = reasons[v.reason] || '無効なニーモニックフレーズです。';
        validityMsg.style.color = '#a94442';
      }
    });

    var fields = buildCommonFields();
    pane.appendChild(fields.frag);

    var submitBtn = el('button', { width: '100%' }, { type: 'button', 'class': 'btn btn-primary' });
    submitBtn.textContent = 'ウォレットをインポート';
    pane.appendChild(submitBtn);

    submitBtn.addEventListener('click', function () {
      var v = validateMnemonic(mnemonicArea.value);
      if (!v.valid) { showMessage(pane, '有効なニーモニックフレーズを入力してください。', true); return; }
      var common = validateCommon(fields, pane);
      if (!common) return;
      submitBtn.disabled = true;
      submitBtn.textContent = 'インポート中...';
      try {
        var privateKey = nemPrivateKeyFromMnemonic(mnemonicArea.value.trim(), common.passphrase, common.accountIndex);
        finalizeWallet(injector, {
          walletName: common.walletName, password: common.password, network: common.network, privateKey: privateKey
        }, function (wallet, loggedIn) {
          submitBtn.textContent = '完了';
          encryptMnemonicBackup(mnemonicArea.value.trim(), common.password).then(function (backup) {
            saveBackup(injector, wallet.accounts[0].address, backup);
          }).catch(function () { /* backup storage is best-effort */ });
          showMessage(pane, loggedIn ? 'ウォレット「' + common.walletName + '」をインポートしました。ダッシュボードに移動します...' : 'ウォレットはインポートされましたが自動的に開けませんでした。ログイン画面から選択してください。', !loggedIn);
          if (onDone) onDone(wallet, loggedIn);
        }, function (msg) {
          submitBtn.disabled = false;
          submitBtn.textContent = 'ウォレットをインポート';
          showMessage(pane, msg, true);
        });
      } catch (e) {
        submitBtn.disabled = false;
        submitBtn.textContent = 'ウォレットをインポート';
        showMessage(pane, 'このニーモニックから鍵を導出できませんでした: ' + e.message, true);
      }
    });

    return pane;
  }


  //////////////////////////////////////////////////////////////////////////
  // Template patches — insert new markup into the app's own real templates
  // (fetched from $templateCache, patched, put back), instead of using a
  // separate floating window. Idempotent: safe to call repeatedly.
  //////////////////////////////////////////////////////////////////////////

  function patchSignupTemplate(injector) {
    try {
      var $templateCache = injector.get('$templateCache');
      var html = $templateCache.get('modules/signup/signup.html');
      if (!html || html.indexOf('hdWalletTypeBtn') !== -1) return;

      var simpleBtnAnchor = '<button class="btn btn-primary" ng-click="$ctrl.changeWalletType(1);$ctrl.start = true;" ng-mouseover="$ctrl.showInfo = 1;">';
      if (html.indexOf(simpleBtnAnchor) === -1) return; // template shape changed: bail out safely

      html = html.replace(simpleBtnAnchor,
        '<button class="btn btn-primary" type="button" id="hdWalletTypeBtn">HDウォレット（ニーモニック）</button>\n        ' + simpleBtnAnchor);

      html = html.replace(
        '<div class="col-md-6 col-md-offset-3" ng-show="!$ctrl._selectedType">',
        '<div class="col-md-6 col-md-offset-3" ng-show="!$ctrl._selectedType" id="walletTypeButtonsRow">'
      );
      html = html.replace(
        '<div class="col-md-offset-3 col-md-6" ng-show="!$ctrl._selectedType">',
        '<div class="col-md-offset-3 col-md-6" ng-show="!$ctrl._selectedType" id="walletTypeInfoRow">'
      );

      var hdContainer = [
        '<div class="col-md-offset-3 col-md-6" id="hdWalletContainer" style="display:none;">',
        '  <div class="form-group text-center">',
        '    <button type="button" class="btn btn-dark" id="hdWalletBackBtn" style="width:auto;"><span class="fa fa-chevron-left" aria-hidden="true"></span> 戻る</button>',
        '  </div>',
        '  <ul class="nav nav-tabs" style="margin-bottom:15px;">',
        '    <li class="active" id="hdTabCreateLi"><a href="" id="hdTabCreate">新規作成</a></li>',
        '    <li id="hdTabImportLi"><a href="" id="hdTabImport">インポート</a></li>',
        '  </ul>',
        '  <div id="hdTabBody"></div>',
        '</div>'
      ].join('\n');

      var insertAnchor = '<!-- Start the signup process -->';
      if (html.indexOf(insertAnchor) === -1) return;
      html = html.replace(insertAnchor, hdContainer + '\n    ' + insertAnchor);

      $templateCache.put('modules/signup/signup.html', html);
    } catch (e) { /* fail safe: signup screen stays exactly as before */ }
  }

  function patchAccountTemplate(injector) {
    try {
      var $templateCache = injector.get('$templateCache');
      var html = $templateCache.get('modules/account/account.html');
      if (!html || html.indexOf('mnemBackupShowBtn') !== -1) return;

      var anchor = '<div class="panel-heading">\n          <h3>{{\'ACCOUNT_EXPORT_MOBILE\' | translate }}</h3>';
      if (html.indexOf(anchor) === -1) return; // template shape changed: bail out safely

      var panels = [
        '<div class="panel-heading">',
        '  <h3>ニーモニックのバックアップ</h3>',
        '</div>',
        '<div class="panel-body">',
        '  <div class="form-group">',
        '    <p class="bg-info">このウォレットをニーモニックフレーズから作成・インポートした場合のみ、パスワードを入力してバックアップを表示できます。</p>',
        '    <div class="input-group">',
        '      <input type="password" class="form-control" id="mnemBackupPw" placeholder="ウォレットのパスワード">',
        '      <span class="input-group-btn showHide">',
        '        <button class="btn btn-primary" type="button" id="mnemBackupShowBtn" style="margin-bottom:15px;"><i class="fa fa-plus"></i></button>',
        '      </span>',
        '    </div>',
        '    <div id="mnemBackupResult"></div>',
        '  </div>',
        '</div>',
        '',
        '<div class="panel-heading">',
        '  <h3>アカウント（ウォレット）の削除</h3>',
        '</div>',
        '<div class="panel-body">',
        '  <p class="bg-info">この端末に保存されているウォレット一覧から削除します。NEMブロックチェーン上のアカウント自体は削除されません。</p>',
        '  <div class="form-group">',
        '    <select class="form-control" id="acctDeleteSelect"></select>',
        '  </div>',
        '  <div id="acctDeleteConfirmArea"></div>',
        '  <button class="btn btn-danger" type="button" id="acctDeleteBtn" style="width:100%;">削除する</button>',
        '</div>',
        ''
      ].join('\n');

      html = html.replace(anchor, panels + anchor);
      $templateCache.put('modules/account/account.html', html);
    } catch (e) { /* fail safe: account screen stays exactly as before */ }
  }


  //////////////////////////////////////////////////////////////////////////
  // Signup page wiring
  //////////////////////////////////////////////////////////////////////////

  function renderSignupTab(injector, which) {
    var body = document.getElementById('hdTabBody');
    var liCreate = document.getElementById('hdTabCreateLi');
    var liImport = document.getElementById('hdTabImportLi');
    if (!body) return;
    liCreate.className = which === 'create' ? 'active' : '';
    liImport.className = which === 'import' ? 'active' : '';
    body.innerHTML = '';
    body.appendChild(which === 'create' ? buildCreatePanel(injector) : buildImportPanel(injector));
  }

  function wireSignupButton(injector, hdBtn) {
    hdBtn.addEventListener('click', function () {
      var row1 = document.getElementById('walletTypeButtonsRow');
      var row2 = document.getElementById('walletTypeInfoRow');
      var container = document.getElementById('hdWalletContainer');
      if (row1) row1.style.display = 'none';
      if (row2) row2.style.display = 'none';
      if (container) container.style.display = '';
      renderSignupTab(injector, 'create');
    });

    var backBtn = document.getElementById('hdWalletBackBtn');
    if (backBtn) backBtn.addEventListener('click', function () {
      var row1 = document.getElementById('walletTypeButtonsRow');
      var row2 = document.getElementById('walletTypeInfoRow');
      var container = document.getElementById('hdWalletContainer');
      if (container) container.style.display = 'none';
      if (row1) row1.style.display = '';
      if (row2) row2.style.display = '';
    });

    var tabCreate = document.getElementById('hdTabCreate');
    var tabImport = document.getElementById('hdTabImport');
    if (tabCreate) tabCreate.addEventListener('click', function (e) { e.preventDefault(); renderSignupTab(injector, 'create'); });
    if (tabImport) tabImport.addEventListener('click', function (e) { e.preventDefault(); renderSignupTab(injector, 'import'); });
  }

  //////////////////////////////////////////////////////////////////////////
  // Account page wiring
  //////////////////////////////////////////////////////////////////////////

  function getCurrentAddress(injector) {
    try {
      var Wallet = injector.get('Wallet');
      return (Wallet.currentAccount && Wallet.currentAccount.address) ||
             (Wallet.current && Wallet.current.accounts && Wallet.current.accounts[0] && Wallet.current.accounts[0].address) || '';
    } catch (e) { return ''; }
  }

  function wireAccountBackup(injector, showBtn) {
    showBtn.addEventListener('click', function () {
      var pwInput = document.getElementById('mnemBackupPw');
      var result = document.getElementById('mnemBackupResult');
      result.innerHTML = '';
      var address = getCurrentAddress(injector);
      var backups = getBackups(injector);
      var backup = backups[address];
      if (!backup) { showMessage(result, 'このウォレットにはニーモニックのバックアップがありません（ニーモニックから作成／インポートしたウォレットのみ対象です）。', true); return; }

      showBtn.disabled = true;
      decryptMnemonicBackup(backup, pwInput.value).then(function (mnemonic) {
        showBtn.disabled = false;
        result.innerHTML = '';
        var box = el('p', { fontFamily: 'monospace', wordBreak: 'break-word' }, { 'class': 'bg-info' });
        box.textContent = mnemonic;
        result.appendChild(box);
        var copyBtn = el('button', { width: '100%' }, { type: 'button', 'class': 'btn btn-default' });
        copyBtn.textContent = 'コピー';
        copyBtn.addEventListener('click', function () {
          try {
            if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(mnemonic);
            copyBtn.textContent = 'コピーしました';
            setTimeout(function () { copyBtn.textContent = 'コピー'; }, 1500);
          } catch (e) { /* ignore */ }
        });
        result.appendChild(copyBtn);
      }).catch(function () {
        showBtn.disabled = false;
        showMessage(result, 'パスワードが違うか、バックアップを読み込めませんでした。', true);
      });
    });
  }

  function refreshDeleteSelect(injector, select) {
    var storage = injector.get('$localStorage');
    var wallets = storage.wallets || [];
    select.innerHTML = '';
    wallets.forEach(function (w, i) {
      var opt = el('option', {}, { value: String(i) });
      opt.textContent = w.name || '(no name)';
      select.appendChild(opt);
    });
  }

  function wireAccountDelete(injector, deleteBtn) {
    var select = document.getElementById('acctDeleteSelect');
    if (select) refreshDeleteSelect(injector, select);

    deleteBtn.addEventListener('click', function () {
      var confirmArea = document.getElementById('acctDeleteConfirmArea');
      confirmArea.innerHTML = '';
      var idx = parseInt(select.value, 10);
      var storage = injector.get('$localStorage');
      var wallets = storage.wallets || [];
      var wallet = wallets[idx];
      if (!wallet) { showMessage(confirmArea, '削除するウォレットを選択してください。', true); return; }

      var warn = el('p', {}, { 'class': 'bg-danger' });
      warn.textContent = 'この端末からウォレット「' + wallet.name + '」を削除します。確認のためウォレット名を入力してください。';
      confirmArea.appendChild(warn);
      var confirmInput = textInput('ウォレット名を正確に入力');
      confirmArea.appendChild(confirmInput);
      var confirmBtn = el('button', { width: '100%', marginTop: '8px' }, { type: 'button', 'class': 'btn btn-danger' });
      confirmBtn.textContent = '削除を確定';
      confirmArea.appendChild(confirmBtn);

      confirmBtn.addEventListener('click', function () {
        if (confirmInput.value !== wallet.name) { showMessage(confirmArea, '名前が一致しません。削除されませんでした。', true); return; }
        try {
          var address = (wallet.accounts && wallet.accounts[0] && wallet.accounts[0].address) || '';
          storage.wallets = wallets.filter(function (w, i) { return i !== idx; });
          deleteBackup(injector, address);

          var wasCurrent = false;
          try {
            var Wallet = injector.get('Wallet');
            if (getCurrentAddress(injector) === address) { wasCurrent = true; Wallet.current = undefined; }
          } catch (e2) { /* best-effort */ }

          injector.get('$rootScope').$applyAsync();
          refreshDeleteSelect(injector, select);
          confirmArea.innerHTML = '';
          showMessage(confirmArea, 'ウォレット「' + wallet.name + '」を削除しました。', false);
          if (wasCurrent) injector.get('$location').path('/login');
        } catch (e) {
          showMessage(confirmArea, '削除に失敗しました: ' + e.message, true);
        }
      });
    });
  }

  //////////////////////////////////////////////////////////////////////////
  // Boot: poll for the injector (mirrors dynamic-nodes.js elsewhere in this
  // app), patch templates once ready, then keep watching the DOM so newly
  // rendered pages get wired up as the user navigates around the app.
  //////////////////////////////////////////////////////////////////////////

  var INJECTOR_POLL_MS = 200;
  var INJECTOR_POLL_MAX = 50;

  function scanAndWire(injector) {
    var hdBtn = document.getElementById('hdWalletTypeBtn');
    if (hdBtn && !hdBtn._mnemonicWired) { hdBtn._mnemonicWired = true; wireSignupButton(injector, hdBtn); }

    var backupBtn = document.getElementById('mnemBackupShowBtn');
    if (backupBtn && !backupBtn._mnemonicWired) { backupBtn._mnemonicWired = true; wireAccountBackup(injector, backupBtn); }

    var deleteBtn = document.getElementById('acctDeleteBtn');
    if (deleteBtn && !deleteBtn._mnemonicWired) { deleteBtn._mnemonicWired = true; wireAccountDelete(injector, deleteBtn); }
  }

  function onInjectorReady(injector) {
    patchSignupTemplate(injector);
    patchAccountTemplate(injector);
    scanAndWire(injector);
    try {
      var observer = new MutationObserver(function () { scanAndWire(injector); });
      observer.observe(document.body, { childList: true, subtree: true });
    } catch (e) { /* MutationObserver unavailable: initial wiring still applied above */ }
  }

  function waitForInjector(attempt) {
    var injector = null;
    try {
      injector = window.angular && angular.element(document).injector();
    } catch (e) {
      injector = null;
    }
    if (injector) {
      try { onInjectorReady(injector); } catch (e) { /* fail safe: rest of the app is unaffected */ }
      return;
    }
    if (attempt >= INJECTOR_POLL_MAX) return;
    setTimeout(function () { waitForInjector(attempt + 1); }, INJECTOR_POLL_MS);
  }

  waitForInjector(0);
})();
