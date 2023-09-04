package main

// countryCodes is a list of supported countries.
var countryCodes = []uint8{
	1,
	2,
	3,
	4,
	5,
	6,
	7,
	8,
	9,
	10,
	11,
	12,
	13,
	14,
	15,
	16,
	17,
	18,
	19,
	20,
	21,
	22,
	23,
	24,
	25,
	26,
	27,
	28,
	29,
	30,
	31,
	32,
	33,
	34,
	35,
	36,
	37,
	38,
	39,
	40,
	41,
	42,
	43,
	44,
	45,
	46,
	47,
	48,
	49,
	50,
	51,
	52,
	53,
	54,
	55,
	56,
	57,
	58,
	59,
	60,
	61,
	62,
	63,
	64,
	65,
	66,
	67,
	68,
	69,
	70,
	71,
	72,
	73,
	74,
	75,
	76,
	77,
	78,
	79,
	80,
	81,
	82,
	83,
	84,
	85,
	86,
	87,
	88,
	89,
	90,
	91,
	92,
	93,
	94,
	95,
	96,
	97,
	98,
	99,
	100,
	101,
	102,
	103,
	104,
	105,
	106,
	107,
	108,
	109,
	110,
	111,
	112,
	113,
	114,
	115,
	116,
	117,
	118,
	119,
	120,
	121,
	122,
	123,
	124,
	125,
	126,
	127,
	128,
	129,
	130,
	131,
	132,
	133,
	134,
	135,
	136,
	137,
	138,
	139,
	140,
	141,
	142,
	143,
	144,
	145,
	146,
	147,
	148,
	149,
	150,
	151,
	152,
	153,
	154,
	155,
	156,
	157,
	158,
	159,
	160,
	161,
	162,
	163,
	164,
	165,
	166,
	167,
	168,
	169,
	170,
	171,
	172,
	173,
	174,
	175,
	176,
	177,
	178,
	179,
	180,
	181,
	182,
	183,
	184,
	185,
	186,
	187,
	188,
	189,
	190,
	191,
	192,
	193,
	194,
	195,
	196,
	197,
	198,
	199,
	200,
	201,
	202,
	203,
	204,
	205,
	206,
	207,
	208,
	209,
	210,
	211,
	212,
	213,
	214,
	215,
	216,
	217,
	218,
	219,
	220,
	221,
	222,
	223,
	224,
	225,
	226,
	227,
	228,
	229,
	230,
	231,
	232,
	233,
	234,
	235,
	236,
	237,
	238,
	239,
	240,
	241,
	242,
	243,
	244,
	245,
	246,
	247,
	248,
	249,
	250,
	251,
	252,
	253,
	254,
}

// numberOfRegions is the amount of provinces/states/prefectures each country has
var numberOfRegions = map[uint8]uint8{
	1:   47,
	2:   18,
	3:   3,
	4:   2,
	5:   32,
	6:   22,
	7:   1,
	8:   1,
	9:   7,
	10:  24,
	11:  1,
	12:  1,
	13:  1,
	14:  6,
	15:  9,
	16:  27,
	17:  5,
	18:  13,
	19:  3,
	20:  13,
	21:  33,
	22:  7,
	23:  1,
	24:  30,
	25:  22,
	26:  14,
	27:  2,
	28:  1,
	29:  1,
	30:  22,
	31:  10,
	32:  9,
	33:  18,
	34:  14,
	35:  1,
	36:  32,
	37:  1,
	38:  1,
	39:  17,
	40:  10,
	41:  18,
	42:  25,
	43:  14,
	44:  1,
	45:  6,
	46:  10,
	47:  12,
	48:  2,
	49:  52,
	50:  19,
	51:  1,
	52:  25,
	53:  11,
	54:  6,
	55:  12,
	56:  7,
	57:  7,
	58:  8,
	59:  6,
	60:  4,
	61:  7,
	62:  1,
	63:  6,
	64:  12,
	65:  14,
	66:  9,
	67:  3,
	68:  3,
	69:  9,
	70:  28,
	71:  4,
	72:  6,
	73:  14,
	74:  17,
	75:  15,
	76:  6,
	77:  26,
	78:  16,
	79:  13,
	80:  20,
	81:  8,
	82:  8,
	83:  20,
	84:  26,
	85:  10,
	86:  2,
	87:  10,
	88:  3,
	89:  8,
	90:  2,
	91:  21,
	92:  11,
	93:  13,
	94:  12,
	95:  17,
	96:  11,
	97:  16,
	98:  7,
	99:  42,
	100: 7,
	101: 3,
	102: 8,
	103: 5,
	104: 9,
	105: 19,
	106: 4,
	107: 21,
	108: 23,
	109: 49,
	110: 5,
	111: 9,
	112: 10,
	113: 10,
	114: 13,
	115: 11,
	116: 8,
	117: 23,
	118: 18,
	119: 6,
	120: 6,
	121: 18,
	122: 1,
	123: 1,
	124: 1,
	125: 1,
	126: 1,
	127: 1,
	128: 25,
	129: 25,
	130: 18,
	131: 22,
	132: 15,
	133: 7,
	134: 8,
	135: 11,
	136: 16,
	137: 8,
	138: 20,
	139: 4,
	140: 7,
	141: 9,
	142: 13,
	143: 1,
	144: 1,
	145: 1,
	146: 2,
	147: 1,
	148: 1,
	149: 4,
	150: 5,
	151: 1,
	152: 33,
	153: 1,
	154: 76,
	155: 18,
	156: 16,
	157: 2,
	158: 1,
	159: 2,
	160: 32,
	161: 34,
	162: 18,
	163: 7,
	164: 7,
	165: 4,
	166: 6,
	167: 13,
	168: 7,
	169: 34,
	170: 27,
	171: 8,
	172: 8,
	173: 6,
	174: 13,
	175: 14,
	176: 4,
	177: 12,
	178: 5,
	179: 19,
	180: 7,
	181: 8,
	182: 2,
	183: 21,
	184: 1,
	185: 1,
	186: 1,
	187: 5,
	188: 1,
	189: 1,
	190: 3,
	191: 3,
	192: 37,
	193: 18,
	194: 10,
	195: 5,
	196: 12,
	197: 13,
	198: 14,
	199: 15,
	200: 5,
	201: 8,
	202: 4,
	203: 14,
	204: 6,
	205: 9,
	206: 3,
	207: 37,
	208: 26,
	209: 10,
	210: 17,
	211: 26,
	212: 12,
	213: 2,
	214: 9,
	215: 2,
	216: 48,
	217: 10,
	218: 3,
	219: 12,
	220: 3,
	221: 24,
	222: 9,
	223: 16,
	224: 4,
	225: 3,
	226: 8,
	227: 22,
	228: 3,
	229: 1,
	230: 5,
	231: 1,
	232: 31,
	233: 4,
	234: 5,
	235: 1,
	236: 9,
	237: 1,
	238: 4,
	239: 4,
	240: 3,
	241: 2,
	242: 1,
	243: 16,
	244: 4,
	245: 2,
	246: 9,
	247: 3,
	248: 5,
	249: 9,
	250: 6,
	251: 1,
	252: 2,
	253: 1,
	254: 5,
}

// languages are all the languages the Everybody Votes Channel supports.
var languages = []LanguageCode{Japanese, English, German, French, Spanish, Italian, Dutch}

// countries are all the countries EVC supports in all languages.
var countries = map[int][]string{
	1:   {"日本", "Japan", "Japan", "Japon", "Japón", "Giappone", "Japan"},
	2:   {"南極大陸", "Antarctica", "Antarktika", "Antarctique", "Antártida", "Antartide", "Antarctica"},
	3:   {"ボネール、シント・ユースタティウスおよびサバ", "Caribbean Netherlands", "Karibische Niederlande", "Pays-Bas caribéens", "Caribe Neerlandés", "Paesi Bassi caraibici", "Caribisch Nederland"},
	4:   {"フォークランド諸島", "Falkland Islands", "Falklandinseln", "Îles Malouines", "Islas Malvinas", "Isole Falkland", "Falklandeilanden"},
	5:   {"スコットランド", "Scotland", "Schottland", "Ecosse", "Escocia", "Scozia", "Schotland"},
	6:   {"ウェールズ", "Wales", "Wales", "Pays de Galles", "Gales", "Galles", "Wales"},
	7:   {"シント・マールテン", "Sint Maarten", "Sint Maarten", "Saint-Martin (Pays-Bas)", "San Martín (Países Bajos)", "Sint Maarten", "Sint Maarten"},
	8:   {"アンギラ", "Anguilla", "Anguilla", "Anguilla", "Anguila", "Anguilla", "Anguilla"},
	9:   {"アンティグア・バーブーダ", "Antigua and Barbuda", "Antigua und Barbuda", "Antigua-et-Barbuda", "Antigua y Barbuda", "Antigua e Barbuda", "Antigua en Barbuda"},
	10:  {"アルゼンチン", "Argentina", "Argentinien", "Argentine", "Argentina", "Argentina", "Argentinië"},
	11:  {"アルバ", "Aruba", "Aruba", "Aruba", "Aruba", "Aruba", "Aruba"},
	12:  {"バハマ", "Bahamas", "Bahamas", "Bahamas", "Bahamas", "Bahamas", "Bahama's"},
	13:  {"バルバドス", "Barbados", "Barbados", "Barbade", "Barbados", "Barbados", "Barbados"},
	14:  {"ベリーズ", "Belize", "Belize", "Belize", "Belice", "Belize", "Belize"},
	15:  {"ボリビア", "Bolivia", "Bolivien", "Bolivie", "Bolivia", "Bolivia", "Bolivia"},
	16:  {"ブラジル", "Brazil", "Brasilien", "Brésil", "Brasil", "Brasile", "Brazilië"},
	17:  {"イギリス領ヴァージン諸島", "British Virgin Islands", "Britische Jungferninseln", "Îles Vierges britanniques", "Islas Vírgenes Británicas", "Isole Vergini Britanniche", "Britse Maagdeneilanden"},
	18:  {"カナダ", "Canada", "Kanada", "Canada", "Canadá", "Canada", "Canada"},
	19:  {"ケイマン諸島", "Cayman Islands", "Kaimaninseln", "Îles Caïmans", "Islas Caimán", "Isole Cayman", "Kaaimaneilanden"},
	20:  {"チリ", "Chile", "Chile", "Chili", "Chile", "Cile", "Chili"},
	21:  {"コロンビア", "Colombia", "Kolumbien", "Colombie", "Colombia", "Colombia", "Colombia"},
	22:  {"コスタリカ", "Costa Rica", "Costa Rica", "Costa Rica", "Costa Rica", "Costa Rica", "Costa Rica"},
	23:  {"ドミニカ国", "Dominica", "Dominica", "Dominique", "Dominica", "Dominica", "Dominica"},
	24:  {"ドミニカ共和国", "Dominican Republic", "Dominikanische Republik", "République dominicaine", "República Dominicana", "Repubblica Dominicana", "Dominicaanse Replubliek"},
	25:  {"エクアドル", "Ecuador", "Ecuador", "Equateur", "Ecuador", "Ecuador", "Ecuador"},
	26:  {"エルサルバドル", "El Salvador", "El Salvador", "Salvador", "El Salvador", "El Salvador", "El Salvador"},
	27:  {"フランス領ギアナ", "French Guiana", "Französisch-Guayana", "Guyane française", "Guayana Francesa", "Guyana francese", "Frans-Guyana"},
	28:  {"グレナダ", "Grenada", "Grenada", "Grenade", "Granada", "Grenada", "Grenada"},
	29:  {"グアドループ", "Guadeloupe", "Guadeloupe", "Guadeloupe", "Guadalupe", "Guadalupa", "Guadeloupe"},
	30:  {"グアテマラ", "Guatemala", "Guatemala", "Guatemala", "Guatemala", "Guatemala", "Guatemala"},
	31:  {"ガイアナ", "Guyana", "Guyana", "République Coopérative de Guyane", "Guyana", "Guyana", "Guyana"},
	32:  {"ハイチ", "Haiti", "Haiti", "Haïti", "Haití", "Haiti", "Haïti"},
	33:  {"ホンジュラス", "Honduras", "Honduras", "Honduras", "Honduras", "Honduras", "Honduras"},
	34:  {"ジャマイカ", "Jamaica", "Jamaika", "Jamaïque", "Jamaica", "Giamaica", "Jamaica"},
	35:  {"マルティニーク", "Martinique", "Martinique", "Martinique", "Martinica", "Martinica", "Martinique"},
	36:  {"メキシコ", "Mexico", "Mexiko", "Mexique", "México", "Messico", "Mexico"},
	37:  {"モントセラト", "Montserrat", "Montserrat", "Montserrat", "Montserrat", "Montserrat", "Montserrat"},
	38:  {"キュラソー島", "Curaçao", "Curaçao", "Curaçao", "Curazao", "Curaçao", "Curaçao"},
	39:  {"ニカラグア", "Nicaragua", "Nicaragua", "Nicaragua", "Nicaragua", "Nicaragua", "Nicaragua"},
	40:  {"パナマ", "Panama", "Panama", "Panama", "Panamá", "Panamá", "Panama"},
	41:  {"パラグアイ", "Paraguay", "Paraguay", "Paraguay", "Paraguay", "Paraguay", "Paraguay"},
	42:  {"ペルー", "Peru", "Peru", "Pérou", "Perú", "Perù", "Peru"},
	43:  {"セントキッツ・ネイビス", "St. Kitts and Nevis", "St. Kitts und Nevis", "Saint-Kitts-et-Nevis", "San Cristóbal y Nieves", "Saint Kitts e Nevis", "Saint Kitts en Nevis"},
	44:  {"セントルシア", "St. Lucia", "St. Lucia", "Sainte-Lucie", "Santa Lucía", "Santa Lucia", "Saint Lucia"},
	45:  {"セントビンセント・グレナディーン", "St. Vincent and the Grenadines", "St. Vincent und die Grenadinen", "Saint-Vincent-et-les-Grenadines", "San Vicente y las Granadinas", "Saint Vincent e Grenadine", "Saint Vincent en de Grenadines"},
	46:  {"スリナム", "Suriname", "Suriname", "Suriname", "Surinam", "Suriname", "Suriname"},
	47:  {"トリニダード・トバゴ", "Trinidad and Tobago", "Trinidad und Tobago", "Trinité-et-Tobago", "Trinidad y Tobago", "Trinidad e Tobago", "Trinidad en Tobago"},
	48:  {"タークス・カイコス諸島", "Turks and Caicos Islands", "Turks- und Caicosinseln", "Îles Turques-et-Caïques", "Islas Turcas y Caicos", "Turks e Caicos", "Turks- en Caicoseilanden"},
	49:  {"アメリカ", "United States", "Vereinigte Staaten", "Etats-Unis d’Amérique", "Estados Unidos de América", "Stati Uniti d'America", "Verenigde Staten"},
	50:  {"ウルグアイ", "Uruguay", "Uruguay", "Uruguay", "Uruguay", "Uruguay", "Uruguay"},
	51:  {"米領バージン諸島", "US Virgin Islands", "Amerikanische Jungferninseln", "Îles Vierges américaines", "Islas Vírgenes Americanas", "Isole Vergini Statunitensi", "Amerikaanse Maagdeneilanden"},
	52:  {"ベネズエラ", "Venezuela", "Venezuela", "Venezuela", "Venezuela", "Venezuela", "Venezuela"},
	53:  {"アルメニア", "Armenia", "Armenien", "Arménie", "Armenia", "Armenia", "Armenië"},
	54:  {"ベラルーシ", "Belarus", "Weißrussland", "Biélorussie", "Bielorrusia", "Bielorussia", "Wit-Rusland"},
	55:  {"ジョージア", "Georgia", "Georgien", "Géorgie", "Georgia", "Georgia", "Goergië"},
	56:  {"コソボ", "Kosovo", "Kosovo", "Kosovo", "Kosovo", "Kosovo", "Kosovo"},
	57:  {"アブハジア", "Abkhazia", "Abchasien", "Abkhazie", "Abjasia", "Abcasia", "Abchazië"},
	58:  {"アルツァフ", "Artsakh", "Republik Arzach", "Artsakh", "Artsaj", "Artsakh", "Artsach"},
	59:  {"北キプロス", "Northern Cyprus", "Nordzypern", "Chypre du Nord", "Chipre del Norte", "Cipro del Nord", "Noord-Cyprus"},
	60:  {"南オセチア", "South Ossetia", "Südossetien", "Ossétie du Sud", "Osetia del Sur", "Ossezia del Sud", "Zuid-Ossetië"},
	61:  {"ドニエストル・モルドバ", "Transnistria", "Transnistrien", "Transnistrie", "Transnistria", "Transnistria", "Transnistrië"},
	62:  {"オーランド諸島", "Åland", "Åland", "Åland", "Åland", "Isole Åland", "Åland"},
	63:  {"フェロー諸島", "Faroe Islands", "Färöe", "Îles Féroé", "Islas Feroe", "Fær Øer", "Faeröer"},
	64:  {"アルバニア", "Albania", "Albanien", "Albanie", "Albania", "Albania", "Albanië"},
	65:  {"オーストラリア", "Australia", "Australien", "Australie", "Australia", "Australia", "Australië"},
	66:  {"オーストリア", "Austria", "Österreich", "Autriche", "Austria", "Austria", "Oostenrijk"},
	67:  {"ベルギー", "Belgium", "Belgien", "Belgique", "Bélgica", "Belgio", "België"},
	68:  {"ボスニア・ヘルツェゴビナ", "Bosnia & Herzegovina", "Bosnien-Herzegowina", "Bosnie-Herzégovine", "Bosnia-Herzegovina", "Bosnia-Erzegovina", "Bosnië en Herzegovina"},
	69:  {"ボツワナ", "Botswana", "Botswana", "Botswana", "Botsuana", "Botswana", "Botswana"},
	70:  {"ブルガリア", "Bulgaria", "Bulgarien", "Bulgarie", "Bulgaria", "Bulgaria", "Bulgarije"},
	71:  {"クロアチア", "Croatia", "Kroatien", "Croatie", "Croacia", "Croazia", "Kroatië"},
	72:  {"キプロス", "Cyprus", "Zypern", "Chypre", "Chipre", "Cipro", "Cyprus"},
	73:  {"チェコ", "Czechia", "Tschechien", "République tchèque", "República Checa", "Repubblica Ceca", "Tsjechië"},
	74:  {"デンマーク", "Denmark", "Dänemark", "Danemark", "Dinamarca", "Danimarca", "Denemarken"},
	75:  {"エストニア", "Estonia", "Estland", "Estonie", "Estonia", "Estonia", "Estland"},
	76:  {"フィンランド", "Finland", "Finnland", "Finlande", "Finlandia", "Finlandia", "Finland"},
	77:  {"フランス", "France", "Frankreich", "France", "Francia", "Francia", "Frankrijk"},
	78:  {"ドイツ", "Germany", "Deutschland", "Allemagne", "Alemania", "Germania", "Duitsland"},
	79:  {"ギリシャ", "Greece", "Griechenland", "Grèce", "Grecia", "Grecia", "Griekenland"},
	80:  {"ハンガリー", "Hungary", "Ungarn", "Hongrie", "Hungría", "Ungheria", "Hongarije"},
	81:  {"アイスランド", "Iceland", "Island", "Islande", "Islandia", "Islanda", "IJsland"},
	82:  {"アイルランド", "Ireland", "Irland", "Irlande", "Irlanda", "Irlanda", "Ierland"},
	83:  {"イタリア", "Italy", "Italien", "Italie", "Italia", "Italia", "Italië"},
	84:  {"ラトビア", "Latvia", "Lettland", "Lettonie", "Letonia", "Lettonia", "Letland"},
	85:  {"レソト", "Lesotho", "Lesotho", "Lesotho", "Lesotho", "Lesotho", "Lesotho"},
	86:  {"リヒテンシュタイン", "Liechtenstein", "Liechtenstein", "Liechtenstein", "Liechtenstein", "Liechtenstein", "Liechtenstein"},
	87:  {"リトアニア", "Lithuania", "Litauen", "Lituanie", "Lituania", "Lituania", "Litouwen"},
	88:  {"ルクセンブルク", "Luxembourg", "Luxemburg", "Luxembourg", "Luxemburgo", "Lussemburgo", "Luxemburg"},
	89:  {"北マケドニア", "North Macedonia", "Nordmazedonien", "Macédoine du Nord", "Macedonia del Norte", "Macedonia del Nord", "Noord-Macedonië"},
	90:  {"マルタ", "Malta", "Malta", "Malte", "Malta", "Malta", "Malta"},
	91:  {"モンテネグロ", "Montenegro", "Montenegro", "Monténégro", "Montenegro", "Montenegro", "Montenegro"},
	92:  {"モザンビーク", "Mozambique", "Mosambik", "Mozambique", "Mozambique", "Mozambico", "Mozambique"},
	93:  {"ナミビア", "Namibia", "Namibia", "Namibie", "Namibia", "Namibia", "Namibië"},
	94:  {"オランダ", "Netherlands", "Niederlande", "Pays-Bas", "Países Bajos", "Paesi Bassi", "Nederland"},
	95:  {"ニュージーランド", "New Zealand", "Neuseeland", "Nouvelle-Zélande", "Nueva Zelanda", "Nuova Zelanda", "Nieuw-Zeeland"},
	96:  {"ノルウェー", "Norway", "Norwegen", "Norvège", "Noruega", "Norvegia", "Noorwegen"},
	97:  {"ポーランド", "Poland", "Polen", "Pologne", "Polonia", "Polonia", "Polen"},
	98:  {"ポルトガル", "Portugal", "Portugal", "Portugal", "Portugal", "Portogallo", "Portugal"},
	99:  {"ルーマニア", "Romania", "Rumänien", "Roumanie", "Rumanía", "Romania", "Roemenië"},
	100: {"ロシア", "Russia", "Russland", "Russie", "Rusia", "Russia", "Rusland"},
	101: {"セルビア", "Serbia", "Serbien", "Serbie", "Serbia", "Serbia", "Servië"},
	102: {"スロバキア", "Slovakia", "Slowakei", "Slovaquie", "Eslovaquia", "Slovacchia", "Slowakije"},
	103: {"スロベニア", "Slovenia", "Slowenien", "Slovénie", "Eslovenia", "Slovenia", "Slovenië"},
	104: {"南アフリカ", "South Africa", "Südafrika", "Afrique du Sud", "Sudáfrica", "Repubblica Sudafricana", "Zuid-Afrika"},
	105: {"スペイン", "Spain", "Spanien", "Espagne", "España", "Spagna", "Spanje"},
	106: {"エスワティニ", "Eswatini", "Swasiland", "Eswatini", "Suazilandia", "eSwatini", "Swaziland"},
	107: {"スウェーデン", "Sweden", "Schweden", "Suède", "Suecia", "Svezia", "Zweden"},
	108: {"スイス", "Switzerland", "Schweiz", "Suisse", "Suiza", "Svizzera", "Zwitserland"},
	109: {"トルコ", "Turkey", "Türkei", "Turquie", "Turquía", "Turchia", "Turkije"},
	110: {"イギリス", "United Kingdom", "Großbritannien", "Royaume-Uni", "Reino Unido", "Regno Unito", "Verenigd Koninkrijk"},
	111: {"ザンビア", "Zambia", "Sambia", "Zambie", "Zambia", "Zambia", "Zambia"},
	112: {"ジンバブエ", "Zimbabwe", "Simbabwe", "Zimbabwe", "Zimbabue", "Zimbabwe", "Zimbabwe"},
	113: {"アゼルバイジャン", "Azerbaijan", "Aserbaidschan", "Azerbaïdjan", "Azerbaiyán", "Azerbaigian", "Azerbeidzjan"},
	114: {"モーリタニア", "Mauritania", "Mauretanien", "Mauritanie", "Mauritania", "Mauritania", "Mauritanië"},
	115: {"マリ", "Mali", "Mali", "Mali", "Malí", "Mali", "Mali"},
	116: {"ニジェール", "Niger", "Niger", "Niger", "Níger", "Niger", "Niger"},
	117: {"チャド", "Chad", "Tschad", "Tchad", "Chad", "Ciad", "Tsjaad"},
	118: {"スーダン", "Sudan", "Sudan", "Soudan", "Sudán", "Sudan", "Soedan"},
	119: {"エリトリア", "Eritrea", "Eritrea", "Erythrée", "Eritrea", "Eritrea", "Eritrea"},
	120: {"ジブチ", "Djibouti", "Dschibuti", "Djibouti", "Yibuti", "Gibuti", "Djibouti"},
	121: {"ソマリア", "Somalia", "Somalia", "Somalie", "Somalia", "Somalia", "Somalië"},
	122: {"アンドラ", "Andorra", "Andorra", "Andorre", "Andorra", "Andorra", "Andorra"},
	123: {"ジブラルタル", "Gibraltar", "Gibraltar", "Gibraltar", "Gibraltar", "Gibilterra", "Gibraltar"},
	124: {"ガーンジー島", "Guernsey", "Guernsey", "Guernesey", "Guernsey", "Guernsey", "Guernsey"},
	125: {"マン島", "Isle of Man", "Isle of Man", "Île de Man", "Isla de Man", "Isola di Man", "Man (eiland)"},
	126: {"ジャージー島", "Jersey", "Jersey", "Jersey", "Jersey", "Jersey", "Jersey (eiland)"},
	127: {"モナコ", "Monaco", "Monaco", "Monaco", "Mónaco", "Monaco (Principato di)", "Monaco"},
	128: {"台湾", "Taiwan", "Taiwan", "Taiwan", "Taiwán", "Taiwan", "Taiwan"},
	129: {"カンボジア", "Cambodia", "Kambodscha", "Cambodge", "Camboya", "Cambogia", "Cambodja"},
	130: {"ラオス", "Laos", "Laos", "Laos", "Laos", "Laos", "Laos"},
	131: {"モンゴル国", "Mongolia", "Mongolei", "Mongolie", "Mongolia", "Mongolia", "Mongolië"},
	132: {"ミャンマー", "Myanmar", "Myanmar", "Birmanie", "Birmania", "Birmania", "Myanmar"},
	133: {"ネパール", "Nepal", "Nepal", "Népal", "Nepal", "Nepal", "Nepal"},
	134: {"ベトナム", "Vietnam", "Vietnam", "Viêt Nam", "Vietnam", "Vietnam", "Vietnam"},
	135: {"北朝鮮", "North Korea", "Nordkorea", "Corée du Nord", "Corea del Norte", "Corea del Nord", "Noord-Korea"},
	136: {"韓国", "South Korea", "Südkorea", "Corée du Sud", "Corea del Sur", "Corea del Sud", "Zuid-Korea"},
	137: {"バングラデシュ", "Bangladesh", "Bangladesch", "Bangladesh", "Bangladés", "Bangladesh", "Bangladesh"},
	138: {"ブータン", "Bhutan", "Bhutan", "Bhoutan", "Bután", "Bhutan", "Bhutan"},
	139: {"ブルネイ", "Brunei", "Brunei", "Brunei", "Brunéi", "Brunei", "Brunei"},
	140: {"モルディブ", "Maldives", "Malediven", "Maldives", "Maldivas", "Maldive", "Maldiven"},
	141: {"スリランカ", "Sri Lanka", "Sri Lanka", "Sri Lanka", "Sri Lanka", "Sri Lanka", "Sri Lanka"},
	142: {"東ティモール", "Timor-Leste", "Osttimor", "Timor oriental", "Timor Oriental", "Timor Est", "Oost-Timor"},
	143: {"イギリス領インド洋地域", "British Indian Ocean Territory", "Britisches Territorium im Indischen Ozean", "Territoire britannique de l'océan Indien", "Territorio Británico del Océano Índico", "Territorio britannico dell'Oceano Indiano", "Brits Indische Oceaanterritorium"},
	144: {"ホンコン", "Hong Kong", "Hongkong", "Hong Kong", "Hong Kong", "Hong Kong", "Hongkong"},
	145: {"マカオ", "Macao", "Macau", "Macao", "Macao", "Macao", "Macau"},
	146: {"クック諸島", "Cook Islands", "Cookinseln", "Îles Cook", "Islas Cook", "Isole Cook", "Cookeilanden"},
	147: {"ニウエ", "Niue", "Niue", "Niue", "Niue", "Niue", "Niue"},
	148: {"ノーフォーク島", "Norfolk Island", "Norfolkinsel", "Île Norfolk", "Isla Norfolk", "Isola Norfolk", "Norfolk"},
	149: {"北マリアナ諸島", "Northern Mariana Islands", "Nördliche Marianen", "Îles Mariannes du Nord", "Islas Marianas del Norte", "Isole Marianne Settentrionali", "Noordelijke Marianen"},
	150: {"アメリカ領サモア", "American Samoa", "Amerikanisch-Samoa", "Samoa américaines", "Samoa Americana", "Samoa Americane", "Amerikaans-Samoa"},
	151: {"グアム", "Guam", "Guam", "Guam", "Guam", "Guam", "Guam"},
	152: {"インドネシア", "Indonesia", "Indonesien", "Indonésie", "Indonesia", "Indonesia", "Indonesië"},
	153: {"シンガポール", "Singapore", "Singapur", "Singapour", "Singapur", "Singapore", "Singapore"},
	154: {"タイ", "Thailand", "Thailand", "Thaïlande", "Tailandia", "Thailandia", "Thailand"},
	155: {"フィリピン", "Philippines", "Philippinen", "Philippines", "Filipinas", "Filippine", "Filipijnen"},
	156: {"マレーシア", "Malaysia", "Malaysia", "Malaisie", "Malasia", "Malaysia", "Maleisië"},
	157: {"サン・バルテルミー島", "Saint Barthélemy", "Saint-Barthélemy", "Saint-Barthélemy", "San Bartolomé", "Saint-Barthélemy", "Saint-Barthélemy"},
	158: {"サン・マルタン", "Saint Martin", "Saint-Martin", "Saint-Martin (France)", "San Martín (Francia)", "Saint-Martin", "Sint-Maarten (Franse Antillen)"},
	159: {"サンピエール島・ミクロン島", "Saint Pierre and Miquelon", "Saint-Pierre und Miquelon", "Saint-Pierre-et-Miquelon", "San Pedro y Miquelón", "Saint-Pierre e Miquelon", "Saint-Pierre en Miquelon"},
	160: {"中国", "China", "China", "Chine", "China", "Cina", "China"},
	161: {"アフガニスタン", "Afghanistan", "Afghanistan", "Afghanistan", "Afganistán", "Afghanistan", "Afghanistan"},
	162: {"カザフスタン", "Kazakhstan", "Kasachstan", "Kazakhstan", "Kazajistán", "Kazakistan", "Kazachstan"},
	163: {"キルギス", "Kyrgyzstan", "Kirgisistan", "Kirghizistan", "Kirguistán", "Kirghizistan", "Kirgizië"},
	164: {"パキスタン", "Pakistan", "Pakistan", "Pakistan", "Pakistán", "Pakistan", "Pakistan"},
	165: {"タジキスタン", "Tajikistan", "Tadschikistan", "Tadjikistan", "Tayikistán", "Tagikistan", "Tadzjikistan"},
	166: {"トルクメニスタン", "Turkmenistan", "Turkmenistan", "Turkménistan", "Turkmenistán", "Turkmenistan", "Turkmenistan"},
	167: {"ウズベキスタン", "Uzbekistan", "Usbekistan", "Ouzbékistan", "Uzbekistán", "Uzbekistan", "Oezbekistan"},
	168: {"アラブ首長国連邦", "U.A.E", "Vereinigte Arabische Emirate", "Emirats arabes unis", "Emiratos Árabes Unidos", "Emirati Arabi Uniti", "Verenigde Arabische Emiraten"},
	169: {"インド", "India", "Indien", "Inde", "India", "India", "India"},
	170: {"エジプト", "Egypt", "Ägypten", "Egypte", "Egipto", "Egitto", "Egypte"},
	171: {"オマーン", "Oman", "Oman", "Oman", "Omán", "Oman", "Oman"},
	172: {"カタール", "Qatar", "Katar", "Qatar", "Catar", "Qatar", "Qatar"},
	173: {"クウェート", "Kuwait", "Kuwait", "Koweït", "Kuwait", "Kuwait", "Koeweit"},
	174: {"サウジアラビア", "Saudi Arabia", "Saudi-Arabien", "Arabie saoudite", "Arabia Saudí", "Arabia Saudita", "Saoedi-Arabië"},
	175: {"シリア", "Syria", "Syrien", "Syrie", "Siria", "Siria", "Syrië"},
	176: {"バーレーン", "Bahrain", "Bahrain", "Bahreïn", "Baréin", "Bahrein", "Bahrein"},
	177: {"ヨルダン", "Jordan", "Jordanien", "Jordanie", "Jordania", "Giordania", "Jordanië"},
	178: {"イラン", "Iran", "Iran", "Iran", "Irán", "Iran", "Iran"},
	179: {"イラク", "Iraq", "Irak", "Irak", "Irak", "Iraq", "Irak"},
	180: {"イスラエル", "Israel", "Israel", "Israël", "Israel", "Israele", "Israël"},
	181: {"レバノン", "Lebanon", "Libanon", "Liban", "Líbano", "Libano", "Libanon"},
	182: {"パレスチナ", "Palestine", "Palästina", "Palestine", "Palestina", "Palestina", "Palestina"},
	183: {"イエメン", "Yemen", "Jemen", "Yémen", "Yemen", "Yemen", "Jemen"},
	184: {"サンマリノ", "San Marino", "San Marino", "Saint-Marin", "San Marino", "San Marino", "San Marino"},
	185: {"バチカン", "Vatican City", "Vatikanstadt", "Vatican", "Vaticano", "Vaticano (Città del)", "Vaticaanstad"},
	186: {"バーミューダ", "Bermuda", "Bermuda", "Bermudes", "Bermudas", "Bermuda", "Bermuda"},
	187: {"フランス領ポリネシア", "French Polynesia", "Französisch-Polynesien", "Polynésie française", "Polinesia Francesa", "Polinesia francese", "Frans-Polynesië"},
	188: {"レユニオン", "Réunion", "Réunion", "La Réunion", "Reunión", "Riunione", "Réunion"},
	189: {"マヨット", "Mayotte", "Mayotte", "Mayotte", "Mayotte", "Mayotte", "Mayotte"},
	190: {"ニューカレドニア", "New Caledonia", "Neukaledonien", "Nouvelle-Calédonie", "Nueva Caledonia", "Nuova Caledonia", "Nieuw-Caledonië"},
	191: {"ウォリス・フツナ", "Wallis and Futuna", "Wallis und Futuna", "Wallis-et-Futuna", "Wallis y Futuna", "Wallis e Futuna", "Wallis en Futuna"},
	192: {"ナイジェリア", "Nigeria", "Nigeria", "Nigeria", "Nigeria", "Nigeria", "Nigeria"},
	193: {"アンゴラ", "Angola", "Angola", "Angola", "Angola", "Angola", "Angola"},
	194: {"ガーナ", "Ghana", "Ghana", "Ghana", "Ghana", "Ghana", "Ghana"},
	195: {"トーゴ", "Togo", "Togo", "Togo", "Togo", "Togo", "Togo"},
	196: {"ベナン", "Benin", "Benin", "Bénin", "Benín", "Benin", "Benin"},
	197: {"ブルキナファソ", "Burkina Faso", "Burkina Faso", "Burkina Faso", "Burkina Faso", "Burkina Faso", "Burkina Faso"},
	198: {"コートジボワール", "Côte d'Ivoire", "Elfenbeinküste", "Côte d'Ivoire", "Costa de Marfil", "Costa d'Avorio", "Ivoorkust"},
	199: {"リベリア", "Liberia", "Liberia", "Libéria", "Liberia", "Liberia", "Liberia"},
	200: {"シエラレオネ", "Sierra Leone", "Sierra Leone", "Sierra Leone", "Sierra Leona", "Sierra Leone", "Sierra Leone"},
	201: {"ギニア", "Guinea", "Guinea", "Guinée", "Guinea", "Guinea", "Guinee"},
	202: {"ギニアビサウ", "Guinea-Bissau", "Guinea-Bissau", "Guinée-Bissau", "Guinea-Bisáu", "Guinea-Bissau", "Guinee-Bissau"},
	203: {"セネガル", "Senegal", "Senegal", "Sénégal", "Senegal", "Senegal", "Senegal"},
	204: {"ガンビア", "The Gambia", "Gambia", "Gambie", "Gambia", "Gambia", "Gambia"},
	205: {"カーボベルデ", "Cape Verde", "Kap Verdes", "Cap-Vert", "Cabo Verde", "Capo Verde", "Kaapverdië"},
	206: {"セントヘレナ・アセンションおよびトリスタンダクーニャ", "Saint Helena, Ascension and Tristan da Cunha", "St. Helena, Ascension und Tristan da Cunha", "Sainte-Hélène, Ascension et Tristan da Cunha", "Santa Elena, Ascensión y Tristán de Acuña", "Sant'Elena, Ascensione e Tristan da Cunha", "Sint-Helena, Ascension en Tristan da Cunha"},
	207: {"モルドバ", "Moldova", "Republik Moldau", "Moldavie", "Moldavia", "Moldavia", "Moldavië"},
	208: {"ウクライナ", "Ukraine", "Ukraine", "Ukraine", "Ucrania", "Ucraina", "Oekraïne"},
	209: {"カメルーン", "Cameroon", "Kamerun", "Cameroun", "Camerún", "Camerun", "Kameroen"},
	210: {"中央アフリカ共和国", "Central African Republic", "Zentralafrikanische Republik", "République centrafricaine", "República Centroafricana", "Repubblica Centrafricana", "Centraal-Afrikaanse Republiek"},
	211: {"コンゴ民主共和国", "Democratic Republic of the Congo", "Demokratischen Republik Kongo", "République démocratique du Congo", "República Democrática del Congo", "Repubblica Democratica del Congo", "Provincies van Congo-Kinshasa"},
	212: {"コンゴ共和国", "Republic of the Congo", "Republik Kongo", "République du Congo", "República del Congo", "Repubblica del Congo", "Congo-Brazzaville"},
	213: {"赤道ギニア", "Equatorial Guinea", "Äquatorialguinea", "Guinée équatoriale", "Guinea Ecuatorial", "Guinea Equatoriale", "Equatoriaal-Guinea"},
	214: {"ガボン", "Gabon", "Gabun", "Gabon", "Gabón", "Gabon", "Gabon"},
	215: {"サントメ・プリンシペ", "São Tomé and Príncipe", "São Tomé und Príncipe", "Sao Tomé-et-Principe", "Santo Tomé y Príncipe", "São Tomé e Príncipe", "Sao Tomé en Principe"},
	216: {"アルジェリア", "Algeria", "Algerien", "Algérie", "Argelia", "Algeria", "Algerije"},
	217: {"エチオピア", "Ethiopia", "Äthiopiens", "Éthiopie", "Etiopía", "Etiopia", "Ethiopië"},
	218: {"リビア", "Libya", "Libyen", "Libye", "Libia", "Libia", "Libië"},
	219: {"モロッコ", "Morocco", "Marokko", "Maroc", "Marruecos", "Marocco", "Marokko"},
	220: {"南スーダン", "South Sudan", "Südsudan", "Soudan du Sud", "Sudán del Sur", "Sudan del Sud", "Zuid-Soedan"},
	221: {"チュニジ", "Tunisia", "Tunesien", "Tunisie", "Túnez", "Tunisia", "Tunesië"},
	222: {"サハラ・アラブ民主共和国", "Sahrawi Arab Democratic Republic", "Demokratische Arabische Republik Sahara", "République arabe sahraouie démocratique", "República Árabe Saharaui Democrática", "Repubblica Democratica Araba dei Sahrawi", "Arabische Democratische Republiek Sahara"},
	223: {"キューバ", "Cuba", "Kuba", "Cuba", "Cuba", "Cuba", "Cuba"},
	224: {"ブルンジ", "Burundi", "Burundi", "Burundi", "Burundi", "Burundi", "Burundi"},
	225: {"コモロ", "Comoros", "Komoren", "Comores", "Comoras", "Comore", "Comoren"},
	226: {"ケニア", "Kenya", "Kenia", "Kenya", "Kenia", "Kenya", "Kenia"},
	227: {"マダガスカル", "Madagascar", "Madagaskar", "Madagascar", "Madagascar", "Madagascar", "Madagaskar"},
	228: {"マラウイ", "Malawi", "Malawi", "Malawi", "Malaui", "Malawi", "Malawi"},
	229: {"モーリシャス", "Mauritius", "Mauritius", "Maurice", "Mauricio", "Mauritius", "Mauritius"},
	230: {"ルワンダ", "Rwanda", "Ruanda", "Rwanda", "Ruanda", "Ruanda", "Rwanda"},
	231: {"セーシェル", "Seychelles", "Seychellen", "Seychelles", "Seychelles", "Seychelles", "Seychellen"},
	232: {"タンザニア", "Tanzania", "Tansania", "Tanzanie", "Tanzania", "Tanzania", "Tanzania"},
	233: {"ウガンダ", "Uganda", "Uganda", "Ouganda", "Uganda", "Uganda", "Oeganda"},
	234: {"フランス領南方・南極地域", "French Southern and Antarctic Lands", "Französische Süd- und Antarktisgebiete", "Terres australes et antarctiques françaises", "Tierras Australes y Antárticas Francesas", "Terre australi e antartiche francesi", "Franse Zuidelijke en Antarctische Gebieden"},
	235: {"ピトケアン諸島", "Pitcairn Islands", "Pitcairninseln", "Îles Pitcairn", "Islas Pitcairn", "Isole Pitcairn", "Pitcairneilanden"},
	236: {"イギリス領南極地域", "British Antarctic Territory", "Britisches Antarktis-Territorium", "Territoire antarctique britannique", "Territorio Antártico Británico", "Territorio antartico britannico", "Brits Antarctisch Territorium"},
	237: {"サウスジョージア・サウスサンドウィッチ諸島", "South Georgia and the South Sandwich Islands", "Südgeorgien und die Südlichen Sandwichinseln", "Géorgie du Sud-et-les îles Sandwich du Sud", "Islas Georgias del Sur y Sándwich del Sur", "Georgia del Sud e Isole Sandwich Australi", "Zuid-Georgia en de Zuidelijke Sandwicheilanden"},
	238: {"ミクロネシア連邦", "Federated States of Micronesia", "Föderierte Staaten von Mikronesien", "États fédérés de Micronésie", "Estados Federados de Micronesia", "Stati Federati di Micronesia", "Micronesia"},
	239: {"フィジー", "Fiji", "Fidschi", "Fidji", "Fiyi", "Figi", "Fiji"},
	240: {"キリバス", "Kiribati", "Kiribati", "Kiribati", "Kiribati", "Kiribati", "Kiribati"},
	241: {"マーシャル諸島", "Marshall Islands", "Marshallinseln", "Îles Marshall", "Islas Marshall", "Isole Marshall", "Marshalleilanden"},
	242: {"ナウル", "Nauru", "Nauru", "Nauru", "Nauru", "Nauru", "Nauru"},
	243: {"パラオ", "Palau", "Palau", "Palaos", "Palaos", "Palau", "Palau"},
	244: {"パプアニューギニア", "Papua New Guinea", "Papua-Neuguinea", "Papouasie-Nouvelle-Guinée", "Papúa Nueva Guinea", "Papua Nuova Guinea", "Papoea-Nieuw-Guinea"},
	245: {"サモア", "Samoa", "Samoa", "Samoa", "Samoa", "Samoa", "Samoa"},
	246: {"ソロモン諸島", "Solomon Islands", "Salomonen", "Îles Salomon", "Islas Salomón", "Isole Salomone", "Salomonseilanden"},
	247: {"トケラウ", "Tokelau", "Tokelau", "Tokelau", "Tokelau", "Tokelau", "Tokelau"},
	248: {"トンガ", "Tonga", "Tonga", "Tonga", "Tonga", "Tonga", "Tonga"},
	249: {"ツバル", "Tuvalu", "Tuvalu", "Tuvalu", "Tuvalu", "Tuvalu", "Tuvalu"},
	250: {"バヌアツ", "Vanuatu", "Vanuatu", "Vanuatu", "Vanuatu", "Vanuatu", "Vanuatu"},
	251: {"クリスマス島", "Christmas Island", "Weihnachtsinsel", "Île Christmas", "Isla de Navidad", "Isola di Natale", "Christmaseiland"},
	252: {"ココス諸島", "Cocos (Keeling) Islands", "Kokosinseln", "Îles Cocos", "Islas Cocos", "Isole Cocos", "Cocoseilanden"},
	253: {"プエルトリコ", "Puerto Rico", "Puerto Rico", "Porto Rico", "Puerto Rico", "Porto Rico", "Puerto Rico"},
	254: {"グリーンランド", "Greenland", "Grönland", "Groenland", "Groenlandia", "Groenlandia", "Groenland"},
}

// countriesSupportedLanguages is a list of languages each country supports.
var countriesSupportedLanguages = map[uint8][]LanguageCode{
	1:   {Japanese, English},
	3:   {English, Dutch},
	4:   {English},
	7:   {English, Spanish, Dutch},
	8:   {English},
	9:   {English},
	10:  {English, Spanish, FrenchCanadian},
	11:  {English, Dutch},
	12:  {English},
	13:  {English},
	14:  {English},
	15:  {English, Spanish},
	16:  {English, Spanish, Portuguese, FrenchCanadian},
	17:  {English},
	18:  {English, Spanish, FrenchCanadian},
	19:  {English},
	20:  {English, Spanish, FrenchCanadian},
	21:  {English, Spanish, FrenchCanadian},
	22:  {English, Spanish, FrenchCanadian},
	23:  {English},
	24:  {English, Spanish},
	25:  {English, Spanish, FrenchCanadian},
	26:  {English, Spanish},
	27:  {English, French},
	28:  {English, French},
	29:  {English, French},
	30:  {English, Spanish, FrenchCanadian},
	31:  {English},
	32:  {English, French},
	33:  {English, Spanish},
	34:  {English},
	35:  {English, French},
	36:  {English, Spanish, FrenchCanadian},
	37:  {English},
	38:  {English, Dutch},
	39:  {English, Spanish},
	40:  {English, Spanish, FrenchCanadian},
	41:  {English, Spanish},
	42:  {English, Spanish, FrenchCanadian},
	43:  {English},
	44:  {English},
	45:  {English},
	46:  {English, Dutch},
	47:  {English, Spanish},
	48:  {English},
	49:  {English, Spanish, FrenchCanadian},
	50:  {English, Spanish},
	51:  {English},
	52:  {English, Spanish, FrenchCanadian},
	53:  {English, Russian},
	54:  {English, Russian},
	55:  {English, Russian},
	56:  {English},
	63:  {English},
	64:  {English},
	65:  {English},
	66:  {German, French, English, Dutch},
	67:  {German, French, English, Dutch},
	68:  {English},
	69:  {English},
	70:  {English},
	71:  {English, Italian},
	72:  {English},
	73:  {English, German},
	74:  {English, German},
	75:  {English, Russian},
	76:  {English, Russian},
	77:  {French, Catalan, German, English},
	78:  {German, English, Russian},
	79:  {English, Spanish, Portuguese, German},
	80:  {English, German, Russian},
	81:  {English},
	82:  {English},
	83:  {English, Italian},
	84:  {English, Russian},
	85:  {English},
	86:  {English, German},
	87:  {English, Russian},
	88:  {English, German, French, Portuguese},
	89:  {English},
	90:  {English, Italian},
	91:  {English},
	92:  {English, Portuguese},
	93:  {English, German},
	94:  {English, Dutch},
	95:  {English},
	96:  {English},
	97:  {English, German},
	98:  {English, Spanish, Portuguese},
	99:  {English, German, Russian},
	100: {English, Russian},
	101: {English},
	102: {English},
	103: {English},
	104: {English},
	105: {English, Spanish, Portuguese, Catalan},
	106: {English},
	107: {English},
	108: {English, German, French, Italian},
	109: {English, German},
	110: {English},
	// TODO: REVIEW
	111: {English},
	112: {English},
	113: {English},
	114: {English, French},
	115: {English, French},
	116: {English, French},
	117: {English, French},
	118: {English},
	119: {English, Italian},
	120: {English, French},
	121: {English},
	122: {English, French, Spanish, Catalan},
	123: {English, Spanish},
	124: {English, French},
	125: {English, Spanish},
	126: {English},
	127: {English, French, Italian},
	128: {English, Japanese},
	129: {English, French},
	130: {English, French},
	131: {English, Russian},
	132: {English},
	133: {English},
	134: {English, French, Russian, Japanese},
	135: {English, Russian, Japanese},
	136: {English, Japanese},
	137: {English},
	138: {English},
	139: {English},
	140: {English},
	141: {English},
	142: {English, Portuguese},
	143: {English},
	144: {English, Japanese},
	145: {English, Portuguese, Japanese},
	146: {English},
	147: {English},
	148: {English},
	149: {English},
	150: {English},
	151: {English, Spanish},
	152: {English},
	153: {English, Japanese},
	154: {English},
	155: {English, Spanish, Japanese},
	156: {English, Japanese},
	157: {English, French},
	158: {English, French, Dutch},
	159: {English, French},
	160: {English, Japanese, Portuguese, Russian},
	161: {English},
	162: {English, Russian},
	163: {English, Russian},
	164: {English},
	165: {English, Russian},
	166: {English, Russian},
	167: {English, Russian},
	168: {English, French},
	169: {English},
	170: {English},
	171: {English},
	172: {English},
	173: {English},
	174: {English},
	175: {English},
	176: {English},
	177: {English},
	178: {English},
	179: {English},
	180: {English, Russian},
	181: {English, French},
	182: {English},
	183: {English},
	184: {English, Italian},
	185: {English, Italian},
	186: {English, Portuguese},
	187: {English, French},
	188: {English, French},
	189: {English, French},
	190: {English, French},
	191: {English, French},
	192: {English},
	193: {English, Portuguese},
	194: {English},
	195: {English, French},
	196: {English, French},
	197: {English, French},
	198: {English, French},
	199: {English},
	200: {English},
	201: {English, French},
	202: {English, Portuguese},
	203: {English, French},
	204: {English},
	205: {English, Portuguese},
	206: {English},
	207: {English, Russian},
	208: {English, Russian},
	209: {English, French},
	210: {English, French},
	211: {English, French},
	212: {English, French},
	213: {English, French, Spanish, Portuguese},
	214: {English, French},
	215: {English, Portuguese},
	216: {English, French},
	217: {English},
	218: {English, French},
	219: {English, French, Spanish},
	220: {English},
	221: {English, French},
	222: {English, Spanish},
	223: {English, Spanish},
	224: {English, French},
	225: {English, French},
	226: {English},
	227: {English, French},
	228: {English},
	229: {English, French},
	230: {English, French},
	231: {English, French},
	232: {English},
	233: {English},
	234: {English, French},
	235: {English},
	236: {English},
	237: {English},
	238: {English},
	239: {English},
	240: {English},
	241: {English},
	242: {English},
	243: {English},
	244: {English},
	245: {English},
	246: {English},
	247: {English},
	248: {English},
	249: {English},
	250: {English, French},
	251: {English},
	252: {English},
	253: {English, Spanish},
	254: {English},
}

var positionTable = map[uint8][]uint8{
	1:   {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2},
	16:  {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1},
	18:  {1, 1, 2, 1, 1, 3, 1, 1, 1, 1, 1, 4, 3},
	21:  {1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0},
	36:  {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	40:  {2, 0, 1, 1, 1, 0, 0, 1, 1, 2},
	49:  {1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	77:  {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0},
	78:  {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	83:  {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	94:  {1, 1, 1, 3, 1, 1, 1, 1, 1, 2, 1, 1},
	105: {1, 1, 1, 1, 3, 5, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	110: {1, 2, 2, 1, 1},
}

// positionData is a list of data for the position table.
// It has something to do with the position of votes on the downloaded map.
var positionData = map[int]string{
	1:   "A2A4C828AF52B964B478AA64AA73AA87AD9BA5969B96A09EADA5A2A987947F8E78A096A5919B9B8782A591AF82AF7AB978AA6EAA6DB364AF73B96BC05AA546AA55AF4BB437B95FC358BA46C350C82DBE26C623CD2DD237C837D728E14849395A",
	16:  "A4862664E8648E1E4141C873D746CD9E7DA0B4467878B99B8746E35385BEC855C2AEE94D82DC4B6996C8A5AAE3699687E15AA064",
	18:  "87BE3CA009981EA064AAC8C3F0A8E1AAC89BD7C3D4BDAAAA50AF1E695C405649505A3C787841647D8E89",
	21:  "7C7D78739BC8695AAA5A71247D468D6B6E6E579887326946969BC896649B9119782D8C8C4BA58D4864B2677B647328194E19875A733E6E825A87",
	36:  "37508FB0786914465A5A69A54B7D98B69B9E8AAF9687E6A07DAF82918C787DA2649B91B476988BA1EBAA5F7D8CBE91A52B6F67B2A5C8C8C899AE738CC8B9D7B4",
	40:  "A05DAF7B1E7373737D5A739BAA5250823AA0",
	49:  "D25E78D252E748E1AA87917D3C7819645A64E04EDC5FC8A0BE872EE628DF18D98C5A3C46A064AA5F7869B46C9191E249DC64EB37A53FAF5087419169A08C5037D2737337735AE440DC55557D2D5AD746E254B95D7D7D2341CD55E84CC87D714BAA7878914164CD69DC3F272F9B46C3645550F0BE",
	77:  "8246DC465AB49196463CA06E28467864AA46E6E6C86E6E3296C87896C84678C88C14505A8C2D508CC8C8BE96",
	78:  "B95A64966EDC9BC8C86E5F417837AF2D7350467841AA3CBEBE919664781E8C8C",
	83:  "7D822328283C324B463264196432821E64466464786E82649682A08CA0A0BE96B9AABEBE96E63CB4",
	94:  "645AC8418C6496288214B40AAA82D223BE08A0C882B4B46E32C8788232C8",
	105: "6E5F64E6A03C3C1EF852E65FCA739AD9A7E6B4E1C8E6EBE1641E7878503CC832AA73468C1E32A0968C28781E783278327832",
	110: "B4B4738732E67846D71E82B4507D",
}

// VoteType is the type of vote sent.
// This can either be an actual vote or prediction.
type VoteType int

const (
	Vote VoteType = iota
	Prediction
)

// LanguageCode is a numerical value that represents
// a supported language in EVC.
type LanguageCode uint8

const (
	Japanese LanguageCode = iota
	English
	German
	French
	Spanish
	Italian
	Dutch
	Portuguese
	FrenchCanadian
	Russian
	Catalan
)

// FileType is the current type of file we are generating
type FileType uint8

const (
	Normal FileType = iota
	Results
	_Question
)

// Locality is whether it is national or worldwide
type Locality uint8

const (
	Worldwide Locality = iota
	National
	All
)
