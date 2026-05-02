import html as html_lib


def html(body):
    return (
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Canno Quest</title>"
        "<link rel='preconnect' href='https://fonts.googleapis.com'>"
        "<link rel='preconnect' href='https://fonts.gstatic.com' crossorigin>"
        "<link href='https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800&family=JetBrains+Mono:wght@500;600;700&family=Space+Grotesk:wght@500;600;700&display=swap' rel='stylesheet'>"
        "<link rel='stylesheet' href='/static/style.css'></head>"
        "<body><div class='app-shell'>"
        "<header class='top-nav'>"
        "<nav class='top-nav-main' aria-label='Основное меню'>"
        "<button id='nav-back' class='top-nav-btn btn btn-outline' type='button'><span class='nav-ico' aria-hidden='true'>←</span>Назад</button>"
        "<a id='nav-home' class='top-nav-btn top-nav-link btn btn-outline' href='/' title='Домой' aria-label='Домой'><span class='nav-ico' aria-hidden='true'>⌂</span><span class='sr-only'>Домой</span></a>"
        "<a class='top-nav-btn top-nav-link btn btn-outline top-nav-icon-btn' href='/admin/login' title='Вход' aria-label='Вход'><span class='nav-ico' aria-hidden='true'>🔐</span><span class='sr-only'>Вход</span></a>"
        "</nav>"
        "</header>"
        "<div class='bg-noise'></div><div class='bg-grid'></div>"
        "<div class='ambient'></div><div class='ambient-2'></div><div class='ambient-3'></div><div class='ambient-4'></div>"
        f"{body}</div>"
        "<script>(function(){"
        "const isHome=window.location.pathname==='/'||window.location.pathname==='';"
        "const reduceMotionQuery=window.matchMedia('(prefers-reduced-motion: reduce)');"
        "const setReduceMotion=(enabled)=>document.documentElement.classList.toggle('reduced-motion',enabled);setReduceMotion(reduceMotionQuery.matches);"
        "if(typeof reduceMotionQuery.addEventListener==='function'){reduceMotionQuery.addEventListener('change',(e)=>setReduceMotion(e.matches));}else if(typeof reduceMotionQuery.addListener==='function'){reduceMotionQuery.addListener((e)=>setReduceMotion(e.matches));}"
        "const backBtn=document.getElementById('nav-back');const homeBtn=document.getElementById('nav-home');"
        "if(isHome&&backBtn){backBtn.style.display='none';}if(isHome&&homeBtn){homeBtn.style.display='none';}"
        "backBtn.addEventListener('click',()=>{if(!isHome&&window.history.length>1){window.history.back();}});"
        "if(!reduceMotionQuery.matches){const cards=document.querySelectorAll('.card');cards.forEach((card)=>{card.addEventListener('mousemove',(e)=>{const r=card.getBoundingClientRect();card.style.setProperty('--mx',((e.clientX-r.left)/r.width*100)+'%');card.style.setProperty('--my',((e.clientY-r.top)/r.height*100)+'%');});});const hero=document.querySelector('.home-card');if(hero){window.addEventListener('scroll',()=>{const y=Math.min(window.scrollY,500);hero.style.opacity=String(1-y/500);hero.style.transform='translateY('+(y*0.2)+'px) scale('+(1-y/10000)+')';},{passive:true});}}"
        "})();</script></body></html>"
    )


def error_page(code, title, message):
    return html(f"<main class='card'><h1>{code}: {html_lib.escape(title)}</h1><p>{html_lib.escape(message)}</p></main>")
