import html as html_lib


def html(body):
    return (
        "<!doctype html><html lang='ru'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Canno Quest</title><link rel='stylesheet' href='/static.css'></head>"
        "<body><div class='app-shell'>"
        "<div class='bg-noise'></div><div class='bg-grid'></div>"
        "<div class='ambient'></div><div class='ambient-2'></div><div class='ambient-3'></div><div class='ambient-4'></div>"
        f"{body}</div>"
        "<script>(function(){"
        "const cards=document.querySelectorAll('.card');"
        "cards.forEach((card)=>{card.addEventListener('mousemove',(e)=>{const r=card.getBoundingClientRect();card.style.setProperty('--mx',((e.clientX-r.left)/r.width*100)+'%');card.style.setProperty('--my',((e.clientY-r.top)/r.height*100)+'%');});});"
        "const hero=document.querySelector('.home-card');if(hero&&!window.matchMedia('(prefers-reduced-motion: reduce)').matches){window.addEventListener('scroll',()=>{const y=Math.min(window.scrollY,500);hero.style.opacity=String(1-y/500);hero.style.transform='translateY('+(y*0.2)+'px) scale('+(1-y/10000)+')';},{passive:true});}"
        "})();</script></body></html>"
    )


def error_page(code, title, message):
    return html(f"<main class='card'><h1>{code}: {html_lib.escape(title)}</h1><p>{html_lib.escape(message)}</p></main>")
