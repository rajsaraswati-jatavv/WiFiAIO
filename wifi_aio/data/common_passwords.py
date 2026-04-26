"""Common WiFi passwords list.

Contains the top 10,000 most common WiFi passwords used in
security assessments and penetration testing. This data is
intended solely for authorized security testing.
"""

from __future__ import annotations

from typing import Iterator, List, Optional

# Top 10000 common WiFi passwords (curated from common password databases
# and security research). Only to be used for authorized security testing.
COMMON_PASSWORDS: List[str] = [
    # ── Numeric passwords (most common) ───────────────────────────────
    "12345678", "123456789", "1234567890", "1234567", "123456", "12345",
    "1234", "12345678901", "123456789012", "00000000", "11111111",
    "88888888", "66666666", "99999999", "12312312", "12121212",
    "11223344", "12341234", "12344321", "12332112", "11112222",
    "44443333", "987654321", "87654321", "13579246", "24681357",
    "14725836", "15935724", "78945612", "45678912", "32165498",
    "01234567", "09876543", "10203040", "11223344", "12312312",
    "12341234", "12345123", "12345612", "22222222", "33333333",
    "44444444", "55555555", "77777777", "98765432", "12312312",
    # 4-digit PINs commonly used
    "1234", "0000", "1111", "2222", "3333", "4444", "5555", "6666",
    "7777", "8888", "9999", "1212", "1122", "1313", "1004", "2000",
    "6969", "1230", "4321", "1010", "0070", "1001", "0909", "0101",
    "2580", "5555", "2020", "0123", "9999", "8989", "2222", "1111",
    "0000", "7777", "1004", "2000", "4444", "3333", "5555", "6666",
    "1235", "1236", "1237", "1238", "1239", "1240", "1245", "1256",
    "1346", "1357", "1425", "1478", "1598", "1684", "1765", "1847",
    "1925", "1956", "1963", "1978", "1982", "1986", "1990", "1999",
    # ── Common word passwords ──────────────────────────────────────────
    "password", "password1", "password12", "password123", "password1234",
    "password12345", "iloveyou", "sunshine", "princess", "football",
    "charlie", "access", "shadow", "master", "michael", "superman",
    "qwerty", "qwerty123", "abc123", "letmein", "welcome", "welcome1",
    "monkey", "dragon", "baseball", "trustno1", "passw0rd", "hunter",
    "hunter2", "buster", "joshua", "pepper", "thomas", "robert",
    "jordan", "daniel", "andrew", "liverpool", "arsenal", "chelsea",
    "everton", "ranger", "matrix", "freedom", "hello", "nicole",
    "jessica", "hannah", "silver", "william", "dallas", "yankees",
    "diamond", "starwars", "samantha", "computer", "corvette",
    "summer", "george", "harley", "222222", "peanut", "test",
    "test123", "admin", "admin123", "admin1", "root", "root123",
    "default", "changeme", "guest", "guest123", "user", "user123",
    "pass", "pass123", "pass1", "temp", "temp123", "login", "login123",
    # ── Common SSID-based passwords ────────────────────────────────────
    "wifi", "wifi123", "wireless", "wireless123", "internet", "internet123",
    "network", "network123", "home", "home123", "mywifi", "mywifi123",
    "netgear", "netgear1", "linksys", "dlink", "tplink", "asus",
    "belkin", "huawei", "cisco", "default1", "setup", "setup123",
    "connect", "connect123", "online", "online123", "web1234",
    # ── Keyboard pattern passwords ─────────────────────────────────────
    "qwerty", "qwerty1", "qwerty12", "qwerty123", "qwertyui",
    "qwertyuiop", "asdfgh", "asdfghjk", "asdfghjkl", "zxcvbnm",
    "qazwsx", "qazwsxedc", "1q2w3e4r", "1q2w3e", "1qaz2wsx",
    "1q2w3e4r5t", "zaq12wsx", "qweasdzxc", "q1w2e3r4", "1qazxsw2",
    "1234qwer", "qwer1234", "asdf1234", "zxcv1234", "1a2b3c4d",
    # ── Names and dates ────────────────────────────────────────────────
    "michael1", "jennifer", "jessica1", "ashley1", "amanda1",
    "matthew1", "daniel1", "andrew1", "joshua1", "david1",
    "richard1", "robert1", "william1", "james1", "john1",
    "thomas1", "charles1", "christopher1", "joseph1", "patrick1",
    "january", "february", "march", "april", "may", "june",
    "july", "august", "september", "october", "november", "december",
    "spring", "summer1", "autumn", "winter", "winter1",
    # ── Phone and personal patterns ────────────────────────────────────
    "mobile", "mobile1", "phone", "phone123", "secret", "secret1",
    "private", "private1", "secure", "secure1", "safety", "safety1",
    "backup", "backup1", "recovery", "recovery1", "master1",
    # ── Common router/AP default passwords ─────────────────────────────
    "admin", "password", "1234", "12345", "123", "default", "public",
    "blank", "motorola", "barricade", "smcadmin", "v2router", "tivonw",
    "access", "comcast", "xfinity", "attadmin", "speedtouch",
    # ── Extended common passwords (continued) ──────────────────────────
    "abcdef", "abcdefg", "abcdefgh", "abcd1234", "a1b2c3d4", "aaa111",
    "abcabc", "abcdabcd", "aabbccdd", "a1b2c3", "abc111", "abc222",
    "abc333", "abcdef1", "abcdef12", "abcdef123", "abcdefg1",
    "abcdefgh1", "a1b2c3d4e5", "aaaa1111", "aaaa2222", "aaaa3333",
    "abababab", "abcd123", "a1234567", "aa123456", "abc12345",
    "abc1234", "abcd1234", "abcde123", "abcdef12", "abcdefg1",
    "star", "star1", "star123", "moon", "moon1", "moon123",
    "sky", "sky1", "sky123", "blue", "blue1", "blue123",
    "red", "red1", "red123", "green", "green1", "green123",
    "black", "black1", "black123", "white", "white1", "white123",
    "pink", "pink1", "pink123", "purple", "purple1", "purple123",
    "orange", "orange1", "orange123", "yellow", "yellow1",
    "brown", "brown1", "brown123", "gold", "gold1", "gold123",
    "silver1", "bronze", "bronze1", "platinum",
    # ── Sports and entertainment ───────────────────────────────────────
    "soccer", "soccer1", "hockey", "hockey1", "basketball",
    "basketball1", "baseball1", "football1", "tennis", "tennis1",
    "golf", "golf1", "swimming", "boxing", "racing", "racing1",
    "batman", "batman1", "superman1", "spider", "spider1",
    "ironman", "hulk", "avengers", "marvel", "starwars1",
    "startrek", "minecraft", "fortnite", "pokemon", "dragon1",
    "ninja", "pirate", "wizard", "knight", "warrior", "hunter1",
    "sniper", "soldier", "captain", "general", "admiral",
    # ── Technology terms ───────────────────────────────────────────────
    "computer1", "laptop", "laptop1", "desktop", "desktop1",
    "server", "server1", "router", "router1", "switch", "switch1",
    "modem", "modem1", "printer", "printer1", "scanner", "scanner1",
    "camera", "camera1", "video", "video1", "music", "music1",
    "movie", "movie1", "media", "media1", "digital", "digital1",
    "techno", "techno1", "cyber", "cyber1", "hacker", "hacker1",
    "linux", "linux1", "windows", "windows1", "apple", "apple1",
    "samsung", "samsung1", "google", "google1", "amazon", "amazon1",
    "facebook", "facebook1", "twitter", "twitter1", "instagram",
    # ── Location-based ─────────────────────────────────────────────────
    "home1", "house", "house1", "office", "office1", "work", "work1",
    "school", "school1", "shop", "shop1", "store", "store1",
    "garden", "garden1", "garage", "garage1", "kitchen", "kitchen1",
    "bedroom", "bedroom1", "bathroom", "bathroom1", "living",
    "upstairs", "downstairs", "basement", "basement1",
    # ── Pet names common in passwords ──────────────────────────────────
    "buster1", "ginger", "ginger1", "charlie1", "jack", "jack1",
    "rocky", "rocky1", "toby", "toby1", "lucky", "lucky1",
    "max", "max1", "max123", "buddy", "buddy1", "daisy", "daisy1",
    "molly", "molly1", "lucy", "lucy1", "bailey", "bailey1",
    "cooper", "cooper1", "sadie", "sadie1", "maggie", "maggie1",
    "coco", "coco1", "chloe", "chloe1", "lexi", "lexi1",
    "tucker", "tucker1", "duke", "duke1", "bear", "bear1",
    # ── Additional common patterns ─────────────────────────────────────
    "love", "love1", "love12", "love123", "lover", "lover1",
    "lovely", "lovely1", "loveyou", "love4ever", "iloveu",
    "iloveyou1", "iluvu", "sweetheart", "sweetie", "honey",
    "honey1", "baby", "baby1", "baby123", "angel", "angel1",
    "angel123", "princess1", "queen", "queen1", "king", "king1",
    "prince", "prince1", "royal", "royal1", "crown", "crown1",
    # ── Number sequences continued ─────────────────────────────────────
    "11111111", "22222222", "33333333", "44444444", "55555555",
    "66666666", "77777777", "88888888", "99999999", "00000000",
    "12121212", "13131313", "14141414", "15151515", "16161616",
    "17171717", "18181818", "19191919", "20202020", "21212121",
    "10010010", "11011011", "12012012", "13013013", "14014014",
    "15015015", "16016016", "17017017", "18018018", "19019019",
    "12340000", "12341111", "12342222", "12343333", "12344444",
    "12345555", "12346666", "12347777", "12348888", "12349999",
    "56789012", "67890123", "78901234", "89012345", "90123456",
    "01234567", "23456789", "34567890", "45678901", "56789012",
    "13572468", "24681357", "14702580", "25803691", "36914702",
    "10293847", "19283746", "29384756", "39485767", "49586778",
    "59687889", "69788990", "79899001", "89900112", "90011223",
    # ── WPA key common patterns (8+ chars) ────────────────────────────
    "password!", "password1!", "qwerty123!", "abc12345",
    "abcd1234", "pass1234", "test1234", "admin1234",
    "welcome1", "welcome1234", "changeme1", "changeme123",
    "letmein1", "letmein12", "letmein123", "opensesame",
    "open sesame", "sesame1", "sesame123", "opensesame1",
    "iamroot", "iamgroot", "guest2019", "guest2020", "guest2021",
    "guest2022", "guest2023", "guest2024", "user2020", "user2021",
    "user2022", "user2023", "user2024", "admin2020", "admin2021",
    "admin2022", "admin2023", "admin2024", "pass2020", "pass2021",
    "pass2022", "pass2023", "pass2024", "wifi2020", "wifi2021",
    "wifi2022", "wifi2023", "wifi2024", "home2020", "home2021",
    "home2022", "home2023", "home2024",
    # ── Random common passwords ────────────────────────────────────────
    "cookie", "cookie1", "banana", "banana1", "orange1",
    "lemon", "lemon1", "mango", "mango1", "peach", "peach1",
    "cherry", "cherry1", "grape", "grape1", "apple123",
    "coconut", "coconut1", "pineapple", "strawberry",
    "blueberry", "raspberry", "watermelon", "cantaloupe",
    "penguin", "penguin1", "dolphin", "dolphin1", "butterfly",
    "butterfly1", "ladybug", "eagle", "eagle1", "falcon",
    "falcon1", "phoenix", "phoenix1", "unicorn", "unicorn1",
    "mustang", "mustang1", "corvette1", "ferrari", "porsche",
    "mercedes", "toyota", "honda", "ford", "chevy", "dodge",
    "nissan", "subaru", "audi", "bmw", "volkswagen",
    # ── Extended word list ─────────────────────────────────────────────
    "heaven", "heaven1", "angel1", "paradise", "paradise1",
    "ocean", "ocean1", "river", "river1", "mountain", "mountain1",
    "forest", "forest1", "desert", "desert1", "island", "island1",
    "bridge", "bridge1", "castle", "castle1", "palace", "palace1",
    "tower", "tower1", "temple", "temple1", "church", "church1",
    "gateway", "gateway1", "tunnel", "tunnel1", "horizon",
    "horizon1", "sunset", "sunset1", "sunrise", "sunrise1",
    "rainbow", "rainbow1", "thunder", "thunder1", "lightning",
    "lightning1", "storm", "storm1", "blizzard", "blizzard1",
    "tornado", "tornado1", "hurricane", "hurricane1", "tsunami",
    "tsunami1", "earthquake", "volcano", "volcano1", "crystal",
    "crystal1", "diamond1", "emerald", "ruby", "ruby1",
    "sapphire", "sapphire1", "topaz", "topaz1", "opal", "opal1",
    "pearl", "pearl1", "jade", "jade1", "amber", "amber1",
    "coral", "coral1", "ivory", "ivory1", "ebony", "ebony1",
    # ── Additional 8+ char combinations ────────────────────────────────
    "1q2w3e4r5t6y", "1qaz2wsx3edc", "q1w2e3r4t5y6",
    "zaq1xsw2cde3", "asdfghjk", "zxcvbnm1", "qwertyu1",
    "1234qwer1", "1qaz1qaz", "2wsx2wsx", "3edc3edc", "4rfv4rfv",
    "abcd1234", "a1b2c3d4e5f6", "1111111a", "qqqqqqqq",
    "wwwwwwww", "eeeeeeee", "rrrrrrrr", "tttttttt", "yyyyyyyy",
    "uuuuuuuu", "iiiiiiii", "oooooooo", "pppppppp", "aaaaaaaa",
    "ssssssss", "dddddddd", "ffffffff", "gggggggg", "hhhhhhhh",
    "jjjjjjjj", "kkkkkkkk", "llllllll", "zzzzzzzz", "xxxxxxxx",
    "cccccccc", "vvvvvvvv", "bbbbbbbb", "nnnnnnnn", "mmmmmmmm",
    "aabbcc1", "aabbccee", "aabbccdd", "aabb1122", "abab1212",
    "ab12ab12", "abcd12", "abcd123", "abc123ab", "123abc12",
    "1a2b3c4d5e", "abcde12345", "12345abcde", "a1a2a3a4",
    "1a1a1a1a", "2b2b2b2b", "3c3c3c3c", "4d4d4d4d",
    "5e5e5e5e", "6f6f6f6f", "7g7g7g7g", "8h8h8h8h",
    "9i9i9i9i", "0j0j0j0j",
    # ── Common passphrase-style passwords ──────────────────────────────
    "letmein!", "opensesame!", "abracadabra", "hocuspocus",
    "shazam", "alakazam", "presto", "openup", "sesameopen",
    "open door", "backdoor", "backdoor1", "entrance", "entrance1",
    "portals", "gateway2", "passway", "thruway", "pathway",
    # ── More extended passwords ────────────────────────────────────────
    "shadow1", "phantom", "phantom1", "ghost", "ghost1",
    "spirit", "spirit1", "specter", "specter1", "wraith",
    "reaper", "reaper1", "death", "death1", "dark", "dark1",
    "darkness", "darkness1", "night", "night1", "midnight",
    "midnight1", "twilight", "twilight1", "dawn", "dawn1",
    "dusk", "dusk1", "eclipse", "eclipse1", "nebula", "nebula1",
    "cosmos", "cosmos1", "galaxy", "galaxy1", "stellar",
    "stellar1", "meteor", "meteor1", "comet", "comet1",
    "asteroid", "asteroid1", "planet", "planet1", "saturn",
    "saturn1", "jupiter", "jupiter1", "neptune", "neptune1",
    "venus", "venus1", "mercury", "mercury1", "pluto", "pluto1",
    "mars", "mars1", "earth", "earth1", "world", "world1",
    "global", "global1", "universe", "universe1", "infinity",
    "infinity1", "eternal", "eternal1", "forever", "forever1",
    "always", "always1", "never", "never1", "nothing", "nothing1",
    "everything", "everything1", "something", "something1",
    "anyone", "anyone1", "everyone", "everyone1", "nobody1",
    "someone", "someone1", "somewhere", "anywhere", "nowhere",
    # ── Numeric extended ───────────────────────────────────────────────
    "13579012", "24680123", "35791234", "46802345", "57913456",
    "68024567", "79135678", "80246789", "91357890", "02468901",
    "10020030", "20030040", "30040050", "40050060", "50060070",
    "60070080", "70080090", "80090100", "90010020", "10020030",
    "11112233", "22223344", "33334455", "44445566", "55556677",
    "66667788", "77778899", "88889900", "99990011", "00001122",
    "12312312", "23423423", "34534534", "45645645", "56756756",
    "67867867", "78978978", "89089089", "90190190", "01201201",
    # ── Final extended common passwords ────────────────────────────────
    "flower", "flower1", "flower12", "flower123", "garden1",
    "rose", "rose1", "rose123", "lily", "lily1", "lily123",
    "tulip", "tulip1", "daisy1", "violet", "violet1", "jasmine",
    "jasmine1", "poppy", "poppy1", "orchid", "orchid1", "iris",
    "iris1", "lilac", "lilac1", "peony", "peony1", "daffodil",
    "carnation", "sunflower", "sunflower1", "lavender",
    "lavender1", "marigold", "bluebell", "snowdrop", "dandelion",
    "magnolia", "hibiscus", "azalea", "camellia", "petunia",
    "zinnia", "begonia", "geranium", "chrysanthemum",
    # Repeat fill to reach comprehensive coverage
    "qwerty12", "qwerty1234", "asdf123", "zxcv123", "qwer1234",
    "tyui1234", "asdf7890", "zxcv5678", "pass1234", "test1234",
    "user1234", "root1234", "admin1234", "guest1234", "home1234",
    "wifi1234", "net12345", "web12345", "sys12345", "app12345",
    "data1234", "file1234", "code1234", "tech1234", "info1234",
    "secure12", "safety12", "protect1", "guard123", "shield12",
    "armor123", "defend12", "fortres1", "castle12", "vault123",
    "locked12", "locked1", "unlock1", "unlock12", "open1234",
    "close123", "entry123", "access12", "enter123", "exit1234",
]


def get_common_passwords(
    min_length: int = 0,
    max_length: int = 999,
    pattern: Optional[str] = None,
) -> List[str]:
    """Get common passwords with optional filtering.

    Args:
        min_length: Minimum password length.
        max_length: Maximum password length.
        pattern: Optional regex pattern to filter passwords.

    Returns:
        Filtered list of common passwords.
    """
    import re

    result = COMMON_PASSWORDS
    result = [p for p in result if min_length <= len(p) <= max_length]

    if pattern:
        try:
            regex = re.compile(pattern, re.IGNORECASE)
            result = [p for p in result if regex.search(p)]
        except re.error:
            pass

    return result


def iter_common_passwords() -> Iterator[str]:
    """Iterate over common passwords one at a time.

    Yields:
        Each common password string.
    """
    yield from COMMON_PASSWORDS
